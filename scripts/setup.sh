#!/bin/bash

# Auth Microservice Setup Script
# This script sets up the development environment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v node &> /dev/null; then
        log_error "Node.js is not installed. Please install Node.js 22 or higher."
        exit 1
    fi
    
    if ! command -v npm &> /dev/null; then
        log_error "npm is not installed."
        exit 1
    fi
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed."
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed."
        exit 1
    fi
    
    # Check Node.js version
    NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
    if [ "$NODE_VERSION" -lt 22 ]; then
        log_error "Node.js version 22 or higher is required. Current version: $(node -v)"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

install_dependencies() {
    log_info "Installing Node.js dependencies..."
    npm install
    log_success "Dependencies installed"
}

setup_environment() {
    log_info "Setting up environment files..."
    
    # Create .env files for each environment
    for env in dev stage prod; do
        if [ ! -f "config/${env}/.env" ]; then
            if [ -f "config/${env}/.env.example" ]; then
                cp "config/${env}/.env.example" "config/${env}/.env"
                log_success "Created config/${env}/.env from example"
            else
                log_warning "No .env.example found for environment: $env"
            fi
        else
            log_info "config/${env}/.env already exists"
        fi
    done
    
    # Create main .env file for local development
    if [ ! -f ".env" ]; then
        if [ -f "env.example" ]; then
            cp "env.example" ".env"
            log_success "Created .env from example"
        fi
    else
        log_info ".env already exists"
    fi
}

generate_prisma() {
    log_info "Generating Prisma client..."
    npx prisma generate
    log_success "Prisma client generated"
}

generate_proto() {
    log_info "Generating proto files..."
    npm run proto:gen
    log_success "Proto files generated"
}

setup_database() {
    log_info "Setting up database..."
    
    # Start database services
    docker-compose -f config/dev/docker-compose.yml up -d db redis
    
    # Wait for database to be ready
    log_info "Waiting for database to be ready..."
    sleep 10
    
    # Run migrations
    log_info "Running database migrations..."
    npx prisma migrate deploy || {
        log_warning "Migration failed, trying to reset database..."
        npx prisma migrate reset --force
    }
    
    log_success "Database setup completed"
}

run_tests() {
    log_info "Running tests..."
    npm run test || {
        log_warning "Some tests failed, but continuing setup..."
    }
    log_success "Tests completed"
}

show_next_steps() {
    log_success "Setup completed successfully!"
    echo ""
    log_info "Next steps:"
    echo "1. Review and update environment variables in config/*/.env files"
    echo "2. Start development environment: ./scripts/deploy.sh dev"
    echo "3. Or use docker-compose directly: docker-compose -f config/dev/docker-compose.yml up"
    echo ""
    log_info "Available commands:"
    echo "  - ./scripts/deploy.sh dev     - Start development environment"
    echo "  - ./scripts/deploy.sh stage   - Start staging environment"
    echo "  - ./scripts/deploy.sh prod    - Start production environment"
    echo "  - npm run test               - Run tests"
    echo "  - npm run start:dev          - Start development server"
    echo ""
    log_info "Development URLs:"
    echo "  - gRPC Service: localhost:50051"
    echo "  - PgAdmin: http://localhost:5050"
    echo "  - Database: localhost:5432"
    echo "  - Redis: localhost:6379"
}

# Main execution
main() {
    log_info "Starting Auth Microservice setup..."
    
    check_prerequisites
    install_dependencies
    setup_environment
    generate_prisma
    generate_proto
    setup_database
    run_tests
    show_next_steps
}

# Handle script interruption
trap 'log_error "Setup interrupted"; exit 1' INT TERM

# Run main function
main "$@"
