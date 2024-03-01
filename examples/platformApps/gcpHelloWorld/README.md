# GCP Hello World Test Application

## Introduction

This directory contains a simple helloworld app that is used to deploy to App Engine in order to test policy when using IAP. 
When a browser or CURL performs a GET to the address of the application, the following message is returned. 
```text
Hello Hexa IAP world! The date is 2024-02-29 22:36:51.844352172 +0000 UTC m=+1295.720039657.
```

## Running on Google App Engine

The Google App Engine is able to deploy the GO Module. Specifically this deployment uses the [Google App Engine Flexible Environment](https://cloud.google.com/appengine/docs/flexible/go/create-app).

If not already done, initialize the app engine environment.

Initialize the project...
```shell
gcloud init
gcloud app create --project=$GCP_PROJECT_ID --region=$GCP_REGION
gcloud components install app-engine-go
```

Enable the following Google APIs...
```shell
gcloud services enable admin.googleapis.com
gcloud services enable storage.googleapis.com
gcloud services enable appengine.googleapis.com
gcloud services enable appengineflex.googleapis.com
gcloud services enable iap.googleapis.com
gcloud services enable cloudbuild.googleapis.com
```

To test and run the GO App locally from the gcpHelloWorld directory run the following...
```shell
go run .
```

To deploy and run the app in Google App Engine, enter the following from the gcpHelloWorld directory...
```shell
gcloud app deploy

// To monitor logs
gcloud app logs tail -s default

// To view app in browser
gcloud app browse
```

Note:  When you initially deploy IAP access is turned off and you should be able to open the page. To turn on, go to the
IAM and Admin -> IAP page and select the deployed app. Toggle "IAP" button. You can add users permitted to access using the "Add Principal" button.

You can also open the application up in the browser at the URL: https://<gcp_project_id>.<region_id>.r.appspot.com

Use the Hexa Admin tool to Add GCP provider and then download available applications (aka policy application points). 

## Running on GKE

This method builds a Docker image that can be run in the Google Kubernetes Environment (GKE).

Make sure you've created and configured a GCP project and updated `.env_gcp.sh` with the GCP Project information from the Google Console Dashboard Project Information window. Leave the K8S
properties unset until the K8S cluster is created below.

Fom the `gcpHelloWorld` directory, set the project environment variables and authenticate to GCloud as follows...

```bash
source ./.env_gcp.sh
gcloud auth login
gcloud components update --quiet

gcloud config set project ${GCP_PROJECT_ID}
```

Enable services needed by GKE and IAP.

```bash
gcloud services enable container.googleapis.com
gcloud services enable containerregistry.googleapis.com
gcloud services enable cloudbuild.googleapis.com
gcloud services enable iap.googleapis.com
```

Configure Docker with credentials to PUSH to the Google Registry. Then build and push the application (from the `gcpHelloWorld` directory)...

```shell
gcloud auth configure-docker

docker buildx build ./ --tag gcr.io/${GCP_PROJECT_ID}/${GCP_PROJECT_NAME}:v1
docker push gcr.io/${GCP_PROJECT_ID}/${GCP_PROJECT_NAME}:v1
```

Create the cluster and initialize the kubectl client to be able to administer GKE.
```shell
// Create the cluster
gcloud beta container --project "${GCP_PROJECT_ID}" \
  clusters create-auto "${K8S_CLUSTER_NAME}" \
  --region ${K8S_CLUSTER_REGION} \
  --release-channel "regular" \
  --network "projects/${GCP_PROJECT_ID}/global/networks/default" \
  --subnetwork "projects/${GCP_PROJECT_ID}/regions/${K8S_CLUSTER_REGION}/subnetworks/default" \
  --cluster-ipv4-cidr "/17" \
  --services-ipv4-cidr "/22"

// Set up local kubernetes configuration
gcloud container clusters get-credentials ${K8S_CLUSTER_NAME} --region ${K8S_CLUSTER_REGION} --project ${GCP_PROJECT_ID}
```

With the cluster information returned (or via the GCP Kubernetes Engine -> Clusters page), update the .env_gcp.sh file with the K8S parameters and then run `source ./.env_gcp.sh`.

```shell
// Create a secret using the clientId and clientsecret from the oauth brand that was created
kubectl create secret generic ${GCP_PROJECT_NAME}-secret \
  --from-literal=client_id=<client-id> \
  --from-literal=client_secret=<client-client_secret>
  
// Set up external IP addresses...
gcloud compute addresses create us-${GCP_PROJECT_NAME}-static-ip --global --ip-version IPV4  
```

Apply the following yaml files to the GKE cluster as follows...
```shell
cd k8s
envsubst < helloWorld-deployment.yaml | kubectl apply -f -
envsubst < helloWorld-backend-config.yaml | kubectl apply -f -
envsubst < helloWorld-service.yaml | kubectl apply -f - 
envsubst < helloWorld-ingress.yaml | kubectl apply -f -
envsubst < helloWorld-managed-certificate.yaml | kubectl apply -f -
```

After a while, the application should be running and you will be able to click on the Ingress link in the Kubernetes cluster admin window.  Note it can take up to 24 hours for
the domain name to be created.

Go to the IAM and Admin -> IAP page, and you will now see the deployed K8S app in IAP.  Click on the IAP column as above to enable IAP and click on "Add Principal" to control access.
