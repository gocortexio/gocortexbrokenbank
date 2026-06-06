pipeline {
  agent any

  environment {
    // ---- Edit these for your AWS account / region ----
    AWS_REGION   = 'ap-southeast-1'
    ECR_REGISTRY = '123456789012.dkr.ecr.ap-southeast-1.amazonaws.com'  // <account-id>.dkr.ecr.<region>.amazonaws.com
    IMAGE_NAME   = 'gocortexbrokenbank'
    IMAGE_TAG    = "${env.BUILD_NUMBER}"   // unique + traceable to this Jenkins build
  }

  options {
    timestamps()
    disableConcurrentBuilds()
  }

  stages {

    stage('Checkout') {
      steps {
        checkout scm
      }
    }

    stage('Build (Python deps)') {
      steps {
        // Repo uses uv (uv.lock). --frozen installs exactly what's locked, no updates.
        // Note: this app pins deliberately vulnerable + native packages (e.g. llama-cpp-python),
        // so this step can be slow. It validates that the locked dependencies resolve and install.
        sh 'uv sync --frozen'
      }
    }

    stage('Test (smoke check)') {
      steps {
        // This repo ships NO unit tests, so there is nothing for pytest to run.
        // We just confirm the core modules compile/import cleanly.
        // The REAL quality gates for this app are the security scans (added later via Cortex).
        sh 'uv run python -m py_compile main.py app.py models.py'
      }
    }

    stage('Docker build') {
      steps {
        sh '''
          docker build \
            -t $ECR_REGISTRY/$IMAGE_NAME:$IMAGE_TAG \
            -t $ECR_REGISTRY/$IMAGE_NAME:latest .
        '''
        // ---- Cortex (later): scan the dependencies / IaC / image layers here ----
      }
    }

    stage('Push to ECR') {
      steps {
        // Cleanest auth: attach an IAM role to this EC2 with ECR push permissions,
        // then the AWS CLI below needs NO stored keys.
        // (Alternative: store an AWS access key pair as a Jenkins credential and
        //  wrap this block in withCredentials.)
        sh '''
          aws ecr get-login-password --region $AWS_REGION \
            | docker login --username AWS --password-stdin $ECR_REGISTRY
          docker push $ECR_REGISTRY/$IMAGE_NAME:$IMAGE_TAG
          docker push $ECR_REGISTRY/$IMAGE_NAME:latest
        '''
        // ---- Cortex (later): scan the pushed image in the registry; block on policy ----
      }
    }

    stage('Deploy to runtime') {
      steps {
        // PLACEHOLDER — fill in once you pick a runtime. Examples:
        //   EKS / Kubernetes:
        //     sh 'kubectl set image deployment/brokenbank app=$ECR_REGISTRY/$IMAGE_NAME:$IMAGE_TAG'
        //   ECS:
        //     sh 'aws ecs update-service --cluster bank --service brokenbank --force-new-deployment'
        //   Docker host over SSH:
        //     sh 'ssh deploy@host "docker pull $ECR_REGISTRY/$IMAGE_NAME:$IMAGE_TAG && docker run ..."'
        echo "Image ready to ship: $ECR_REGISTRY/$IMAGE_NAME:$IMAGE_TAG"
        // ---- Cortex (later): runtime protection (CWPP) guards the running workload ----
      }
    }
  }

  post {
    success { echo "Pipeline passed. Image: ${env.ECR_REGISTRY}/${env.IMAGE_NAME}:${env.IMAGE_TAG}" }
    failure { echo 'Pipeline failed — check the failing stage above.' }
    always  { sh 'docker logout $ECR_REGISTRY || true' }
  }
}
