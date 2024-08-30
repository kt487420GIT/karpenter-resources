# Karpenter Setup and Deployment

## Introduction

This repository contains the resources and scripts required to set up and deploy Karpenter, an open-source Kubernetes node autoscaler. Karpenter automatically adjusts the size of your Kubernetes cluster, ensuring that the right amount of compute capacity is available to meet your application's needs. This setup is optimized for AWS EKS and includes a workflow to automate the deployment process.

## Prerequisites

Before you begin, ensure that you have the following prerequisites installed and configured:

- AWS Account: An AWS account with appropriate permissions to create and manage
  EKS clusters, IAM roles, and other resources.
- GitHub Actions Runner: Configured with the necessary permissions to run workflows on your repository.
- EKS Cluster: An existing EKS cluster where Karpenter will be deployed.

## Steps to Set Up

Follow these steps to set up and deploy Karpenter:

1. Create a role with Github repo trust relationships. You can refer role/github-access-policy and role/trust-relationships code(don't forgot to update placeholders).

2. Update GitHub repository secrets and variables:

   - KARPENTER_ROLE: The ARN of the IAM role that GitHub Actions will assume to access your AWS resources, specifically for the Karpenter setup.
   - AWS_REGION: The AWS region where your EKS cluster is deployed.
   - CLUSTER_NAME: The name of your EKS cluster.
   - AMD_AMI_ID: The Amazon Machine Image (AMI) ID for AMD-based EC2 instances that will be used by Karpenter. This AMI should be compatible with your Kubernetes version.
   - K8S_VERSION: The Kubernetes version that your EKS cluster is running. This ensures compatibility with the AMI and other configurations.
   - KARPENTER_NAMESPACE: The Kubernetes namespace where Karpenter is installed. This namespace is where Karpenter's resources and controllers will be deployed.
   - KARPENTER_VERSION: The version of Karpenter that you are deploying. This version should match the one compatible with your Kubernetes cluster and configuration.
   - NODEGROUP_LABEL: The label assigned to the nodes managed by Karpenter, often used for identifying or grouping nodes within the cluster.

3. Configure the GitHub Workflow
   The repository contains a GitHub Actions workflow (.github/workflows/main.yml) that automates the deployment of Karpenter.

4. Run the Workflow
   To deploy Karpenter, manually trigger the GitHub Actions workflow:

   - Go to the GitHub Actions tab in your repository.
   - Select the Run Karpenter Script workflow.
   - Click on the Run workflow dropdown.
   - Specifying the script name (karpenter-python-script.py) as input, trigger the workflow manually.

5. Verify the Deployment
   Once the workflow completes, verify that Karpenter is installed and running:

   ```
   kubectl get pods -n kube-system
   ```

   Check that the Karpenter pods are running without errors.

6. Testing
   To verify the functionality of Karpenter and the NodePool, you can deploy a test workload that will trigger the autoscaler:

   - Run the following command to create a test deployment with zero replicas:

   ```
   kubectl apply -f inflate-deployment.yaml
   ```

7. Scale the deployment to 20 replicas to trigger Karpenter to provision additional nodes:

   ```
   kubectl scale deployment inflate --replicas 20
   ```

8. Check the status of the pods and nodes to ensure that the required capacity has been provisioned:

   ```
   kubectl get pods
   kubectl get nodes
   ```

9. To monitor Karpenter's activity, check the logs:

   ```
   kubectl logs -f -n <KARPENTER_NAMESPACE> -l app.kubernetes.io/name=karpenter -c controller
   ```

## NOTE:-

1. The karpenter script includes a NodePool configuration to ensure that only instances with up to 8 CPUs are used. You can customize this configuration as needed in the NodePool manifest.

2. Deployment file musht have a topologySpreadConstraints field:

   ```
   topologySpreadConstraints:
       - maxSkew: 1
         topologyKey: capacity-spread
         whenUnsatisfiable: DoNotSchedule
         labelSelector:
           matchLabels:
             app: <app_name>
   ```

3. I am using this AMD AMI: "ami-02bb8bd60dfa800ef" you can also get the latest AMI by running the below command:

   ```
   aws ssm get-parameter --name /aws/service/eks/optimized-ami/${K8S_VERSION}/amazon-linux-2/recommended/image_id --query Parameter.Value --output text
   ```

## Reference

- [Karpenter Documentation](https://karpenter.sh/docs/getting-started/migrating-from-cas/).
