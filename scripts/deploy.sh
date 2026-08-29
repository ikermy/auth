#!/bin/bash

# Auth Microservice Deployment Script
# Usage: ./scripts/deploy.sh [dev|stage|prod]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="auth_microservice"
REGISTRY="ghcr.io"
IMAGE_NAME="${REGISTRY}/${PROJECT_NAME}"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_environment() {
    local env=$1
    if [[ ! "$env" =~ ^(dev|stage|prod)$ ]]; then
        log_error "Invalid environment: $env. Must be one of: dev, stage, prod"
        exit 1
    fi
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed or not in PATH"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

pull_latest_image() {
    local env=$1
    local tag=$env
    
    log_info "Pulling latest image for environment: $env"
    
    if [ "$env" = "prod" ]; then
        tag="latest"
    fi
    
    docker pull "${IMAGE_NAME}:${tag}" || {
        log_warning "Failed to pull image ${IMAGE_NAME}:${tag}. Building locally..."
        build_image $env
    }
}

build_image() {
    local env=$1
    
    log_info "Building image for environment: $env"
    
    docker build -f "config/${env}/Dockerfile" -t "${IMAGE_NAME}:${env}" . || {
        log_error "Failed to build image for environment: $env"
        exit 1
    }
    
    log_success "Image built successfully"
}

deploy_environment() {
    local env=$1
    
    log_info "Deploying to environment: $env"
    
    # Stop existing containers
    log_info "Stopping existing containers..."
    docker-compose -f "config/${env}/docker-compose.yml" down || true
    
    # Start new containers
    log_info "Starting new containers..."
    docker-compose -f "config/${env}/docker-compose.yml" up -d || {
        log_error "Failed to start containers for environment: $env"
        exit 1
    }
    
    # Wait for services to be healthy
    log_info "Waiting for services to be healthy..."
    sleep 30
    
    # Check health
    check_health $env
}

check_health() {
    local env=$1
    
    log_info "Checking service health..."
    
    # Check if the main application is responding
    if docker-compose -f "config/${env}/docker-compose.yml" ps | grep -q "Up"; then
        log_success "Services are running"
    else
        log_error "Some services are not running properly"
        docker-compose -f "config/${env}/docker-compose.yml" ps
        exit 1
    fi
    
    # Additional health checks can be added here
    # For example, checking if the gRPC service is responding
}

cleanup() {
    local env=$1
    
    log_info "Cleaning up unused Docker resources..."
    docker system prune -f
    docker volume prune -f
}

show_status() {
    local env=$1
    
    log_info "Deployment Status for environment: $env"
    docker-compose -f "config/${env}/docker-compose.yml" ps
}

# Main execution
main() {
    local environment=${1:-dev}
    
    log_info "Starting deployment for environment: $environment"
    
    check_environment $environment
    check_prerequisites
    
    # Pull or build image
    if [ "$environment" = "dev" ]; then
        build_image $environment
    else
        pull_latest_image $environment
    fi
    
    # Deploy
    deploy_environment $environment
    
    # Cleanup
    cleanup $environment
    
    # Show status
    show_status $environment
    
    log_success "Deployment completed successfully for environment: $environment"
    
    # Show useful information
    case $environment in
        "dev")
            log_info "Development environment is available at:"
            log_info "  - gRPC: localhost:50051"
            log_info "  - PgAdmin: http://localhost:5050"
            ;;
        "stage")
            log_info "Staging environment is available at:"
            log_info "  - gRPC: your-staging-server:50051"
            log_info "  - PgAdmin: http://your-staging-server:5050"
            ;;
        "prod")
            log_info "Production environment is available at:"
            log_info "  - gRPC: your-production-server:50051"
            log_info "  - Monitoring: http://your-production-server:3000"
            log_info "  - Metrics: http://your-production-server:9090"
            ;;
    esac
}

# Handle script interruption
trap 'log_error "Deployment interrupted"; exit 1' INT TERM

# Run main function
main "$@"
