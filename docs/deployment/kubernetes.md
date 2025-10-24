# Kubernetes Deployment Guide

This guide provides instructions for deploying the `cbc-auth` service to a Kubernetes cluster.

## Prerequisites

- A running Kubernetes cluster
- `kubectl` configured to connect to your cluster
- An Ingress controller (e.g., NGINX) installed in your cluster

## Deployment Steps

1.  **Create a namespace:**
    ```sh
    kubectl create namespace cbc-auth
    ```

2.  **Create secrets:**
    Create a `secrets.yaml` file based on `deployments/kubernetes/secret.yaml` with your base64-encoded credentials. Then apply it:
    ```sh
    kubectl apply -f secrets.yaml -n cbc-auth
    ```

3.  **Create a configmap:**
    ```sh
    kubectl apply -f deployments/kubernetes/configmap.yaml -n cbc-auth
    ```

4.  **Deploy the application:**
    ```sh
    kubectl apply -f deployments/kubernetes/deployment.yaml -n cbc-auth
    ```

5.  **Expose the service:**
    ```sh
    kubectl apply -f deployments/kubernetes/service.yaml -n cbc-auth
    ```

6.  **Configure Ingress:**
    Update `deployments/kubernetes/ingress.yaml` with your domain and TLS secret, then apply it:
    ```sh
    kubectl apply -f deployments/kubernetes/ingress.yaml -n cbc-auth
    ```

## Verification

Check the status of the deployment:
```sh
kubectl get pods -n cbc-auth
```
You should see the `cbc-auth-service` pods in the `Running` state.

<!--Personal.AI order the ending-->