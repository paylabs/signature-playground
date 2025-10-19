pipeline {
    agent { label 'ahmad-paylabs' }

    environment {
        IMAGE_NAME   = "paylabs-signature-playground"
        IMAGE_TAG    = "${BUILD_NUMBER}"
        COMPOSE_PATH = "docker/docker-compose.yml"
        CERT_PATH    = "docker/certs"
    }

    stages {

        stage('Checkout') {
            steps {
                echo "📦 Checking out repository..."
                git branch: 'main',
                    credentialsId: 'ahmad-gitlab',
                    url: 'https://gitlab.local/paylabs/api-improvement/signature-playgroung.git'
            }
        }

        stage('Generate Self-Signed Certificate') {
            steps {
                echo "🔐 Generating SSL certificate for sign.play ..."
                sh '''
                    mkdir -p docker/certs

                    # Detect local IP dynamically (first non-loopback IP)
                    HOST_IP=$(hostname -I | awk "{print $1}")
                    echo "Detected IP: $HOST_IP"

                    # Generate self-signed certificate valid for DNS and IP
                    openssl req -x509 -newkey rsa:2048 -nodes \
                        -keyout docker/certs/sign.play-key.pem \
                        -out docker/certs/sign.play.pem \
                        -subj "/CN=sign.play" \
                        -addext "subjectAltName=DNS:sign.play,IP:$HOST_IP" \
                        -sha256 -days 365
                '''
            }
        }

        stage('Build Frontend') {
            steps {
                echo "🧱 Building frontend (Vite React)..."
                sh '''
                    npm ci
                    npm run build
                '''
            }
        }

        stage('Build Nginx Image (HTTPS Only)') {
            steps {
                echo "🔧 Building Podman image..."
                sh '''
                    podman build -f docker/Dockerfile -t ${IMAGE_NAME}:${IMAGE_TAG} .
                '''
            }
        }

        stage('Deploy via Podman Compose') {
            steps {
                echo "🚀 Deploying container stack..."
                dir('docker') {
                    sh '''
                        podman-compose down || true
                        podman-compose -f ${COMPOSE_PATH} up -d
                    '''
                }
            }
        }
    }

    post {
        success {
            echo "✅ HTTPS deployed successfully at https://sign.play"
        }
        failure {
            echo "❌ Build failed — check Podman or Jenkins logs."
        }
    }
}