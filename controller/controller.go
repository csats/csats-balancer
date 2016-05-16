/*
Copyright 2015 The Kubernetes Authors All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"reflect"
	"text/template"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/extensions"
	client "k8s.io/kubernetes/pkg/client/unversioned"
	"k8s.io/kubernetes/pkg/fields"
	"k8s.io/kubernetes/pkg/labels"
	"k8s.io/kubernetes/pkg/util"
)

const (
	nginxConf = `
worker_processes  5;  ## Default: 1

worker_rlimit_nofile 8192;
events {
  worker_connections 4096;
}

http {
  error_log /var/log/nginx/error.log info;
  # http://nginx.org/en/docs/http/ngx_http_core_module.html
  types_hash_max_size 2048;
  server_names_hash_max_size 512;
  server_names_hash_bucket_size 64;
  client_max_body_size 50M;

  ssl_certificate /ssl/certchain.pem;
  ssl_certificate_key /ssl/key.pem;

  # performance enhancement for SSL
  ssl_stapling on;
  ssl_session_cache shared:SSL:10m;
  ssl_session_timeout 5m;

  # Disable all weak ciphers
  ssl_ciphers "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4";
  # enables TLSv1.0, 1.1, and 1.2 but not SSLv2 or 3 as they are both weak and
  # deprecated.
  ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
  # Specifies that server ciphers should be preferred over client (e.g.
  # browser) ciphers when using SSL/TLS.
  ssl_prefer_server_ciphers on;

  # config to enable HSTS(HTTP Strict Transport Security)
  # https://developer.mozilla.org/en-US/docs/Security/HTTP_Strict_Transport_Security
  # to avoid ssl stripping https://en.wikipedia.org/wiki/SSL_stripping#SSL_stripping
  add_header Strict-Transport-Security "max-age=31536000;";

  # HTTP redirect
  server {
    listen 80;
    location /.well-known {
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto $scheme;
      proxy_pass http://letsencrypt.default.svc.cluster.local;
    }

    location / {
      return 301 https://$host$request_uri;
    }
  }

  server {
    listen 443 ssl;
    server_name _;

    location / {
      return 503;
    }
  }

{{range $entry := .}}

  {{if $entry.Paths}}
    {{range $path := $entry.Paths}}
      upstream {{$path.ServiceName}} {
        {{range $endpoint := $path.Endpoints}}
          server {{$endpoint}}:{{$path.ServicePort}};
        {{end}}
      }
    {{end}}

    server {
      listen 443 ssl;
      server_name {{$entry.Host}};
      {{range $path := $entry.Paths}}
        location {{$path.Path}} {
          proxy_set_header X-Forwarded-For $remote_addr; # preserve client IP
          proxy_set_header Host $http_host;
          proxy_set_header X-NginX-Proxy true;


          add_header P3P 'CP="Please contact support."';

          proxy_redirect off;

          # Handle Web Socket connections
          proxy_http_version 1.1;
          proxy_set_header Upgrade $http_upgrade;
          proxy_set_header Connection "upgrade";
          proxy_pass http://{{$path.ServiceName}};
        }
      {{end}}
    }
  {{end}}
{{end}}
}`
)

func shellOut(cmd string) {
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		log.Fatalf("Failed to execute %v: %v, err: %v", cmd, string(out), err)
	}
}

type TmplPath struct {
	Path, ServiceName, ServicePort string
	Endpoints                      []string
}

type TmplData struct {
	Host  string
	Paths []TmplPath
}

func main() {
	var ingClient client.IngressInterface
	var podClient client.PodInterface
	var serviceClient client.ServiceInterface
	var namespace = os.Getenv("NAMESPACE")
	var namespaceStr = ""
	if namespace == "" {
		namespace = api.NamespaceAll
		namespaceStr = "ALL"
	} else {
		namespaceStr = namespace
	}
	log.Printf("Starting csats-balancer for namespace %s", namespaceStr)
	if kubeClient, err := client.NewInCluster(); err != nil {
		log.Fatalf("Failed to create client: %v.", err)
	} else {
		ingClient = kubeClient.Extensions().Ingress(namespace)
		podClient = kubeClient.Pods(namespace)
		serviceClient = kubeClient.Services(namespace)
	}
	tmpl, _ := template.New("nginx").Parse(nginxConf)
	rateLimiter := util.NewTokenBucketRateLimiter(0.1, 1)
	knownIngresses := &extensions.IngressList{}
	knownPods := &api.PodList{}
	knownServices := &api.ServiceList{}

	// Controller loop
	shellOut("nginx")
	for {
		rateLimiter.Accept()

		ingresses, err := ingClient.List(labels.Everything(), fields.Everything())
		if err != nil {
			log.Printf("Error retrieving ingresses: %v", err)
			continue
		}

		pods, err := podClient.List(labels.Everything(), fields.Everything())
		if err != nil {
			log.Printf("Error retrieving pods: %v", err)
			continue
		}

		services, err := serviceClient.List(labels.Everything(), fields.Everything())
		if err != nil {
			log.Printf("Error retrieving services: %v", err)
			continue
		}

		if reflect.DeepEqual(ingresses.Items, knownIngresses.Items) &&
			reflect.DeepEqual(pods.Items, knownPods.Items) &&
			reflect.DeepEqual(services.Items, knownServices.Items) {
			// log.Printf("Not reloading nginx")
			continue
		}

		knownIngresses = ingresses
		knownPods = pods
		knownServices = services

		// Build a map from service names to list of pod endpoints
		serviceMap := make(map[string]api.Service)
		endpointMap := make(map[string][]string)
		for serviceIdx := 0; serviceIdx < len(services.Items); serviceIdx++ {
			service := services.Items[serviceIdx]
			endpointMap[service.Name] = make([]string, 0)
			serviceMap[service.Name] = service
			pods, err := podClient.List(labels.SelectorFromSet(service.Spec.Selector), fields.Everything())
			if err != nil {
				log.Printf("Error retrieving services: %v", err)
				continue
			}
			for podIdx := 0; podIdx < len(pods.Items); podIdx++ {
				pod := pods.Items[podIdx]
				if len(pod.Status.PodIP) > 0 {
					endpointMap[service.Name] = append(endpointMap[service.Name], pod.Status.PodIP)
				}
			}
		}

		// Build a list of TmplData mapping ingresses to services
		var data []TmplData
		for ingressIdx := 0; ingressIdx < len(ingresses.Items); ingressIdx++ {
			ingress := ingresses.Items[ingressIdx]
			for ruleIdx := 0; ruleIdx < len(ingress.Spec.Rules); ruleIdx++ {
				rule := ingress.Spec.Rules[ruleIdx]
				ruleTmplData := TmplData{
					Host:  rule.Host,
					Paths: make([]TmplPath, 0),
				}
				for pathIdx := 0; pathIdx < len(rule.HTTP.Paths); pathIdx++ {
					path := rule.HTTP.Paths[pathIdx]
					var port string
					for _, portBlock := range serviceMap[path.Backend.ServiceName].Spec.Ports {
						portStr := fmt.Sprintf("%d", portBlock.Port)
						targetPortStr := fmt.Sprintf("%d", portBlock.TargetPort.IntVal)
						if portStr == path.Backend.ServicePort.String() {
							port = targetPortStr
						}
					}
					if port == "" {
						log.Printf("Error looking up target port for service %s, skipping. Perhaps the service doesn't exist?", path.Backend.ServiceName)
						continue
					}
					ruleTmplData.Paths = append(ruleTmplData.Paths, TmplPath{
						Path:        path.Path,
						ServiceName: path.Backend.ServiceName,
						ServicePort: port,
						Endpoints:   endpointMap[path.Backend.ServiceName],
					})
				}
				data = append(data, ruleTmplData)
			}
		}

		// Render to file using that data and our template
		if w, err := os.Create("/etc/nginx/nginx.conf"); err != nil {
			log.Fatalf("Failed to open %v: %v", nginxConf, err)
		} else if err := tmpl.Execute(w, data); err != nil {
			log.Fatalf("Failed to write template %v", err)
		}
		log.Printf("[%s] Reloading nginx", namespaceStr)
		shellOut("nginx -s reload")
	}
}
