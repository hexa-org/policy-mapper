#export GCP_PROJECT_FOLDER="<your-folder-number>"
#export GCP_BILLING_ACCOUNT="<0X0X0X-0X0X0X-0X0X0X>"

# Update using values from http://console.cloud.google.com  Dashboard Project Info window
export GCP_PROJECT_NAME="<project_name>"
export GCP_PROJECT_ID="<project_id>"
export GCP_PROJECT_NUMBER="<project_number>"
export GCP_SUPPORT_EMAIL="<support_email_contact>"
export GCP_REGION="<deployment_region"

# The following values used with creating Kubernetes Cluster
export K8S_CLUSTER_NAME="<cluster_name>"
export K8S_CLUSTER_REGION="<cluster_region>"

# When an app is deployed, obtain the JWT audience code by clicking "..." on the application in IAM and Admin -> IAP panel
# Note this is not necessary for the hello world application as it does not consume tokens.
export IAP_JWT_AUDIENCE_CODE="<iap_audience_code>"