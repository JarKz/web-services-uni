#!/bin/sh

kubectl create configmap user-service --from-env-file=./user_service/.env
kubectl create configmap library-service --from-env-file=./library_service/.env
kubectl create configmap borrowing-service --from-env-file=./borrowing_service/.env

kubectl apply -f user_service/deployment.yml
kubectl apply -f user_service/service.yml
kubectl apply -f library_service/deployment.yml
kubectl apply -f library_service/service.yml
kubectl apply -f borrowing_service/deployment.yml
kubectl apply -f borrowing_service/service.yml
