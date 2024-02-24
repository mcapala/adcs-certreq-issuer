helm template adcs-issuer  charts/adcs-issuer  -n adcs-issuer --values charts/adcs-issuer/values.yaml

helm template adcs-issuer charts/adcs-issuer -n adcs-issuer --values charts/adcs-issuer/values.yaml > adcs-issuer-all.yaml

kubectl -n adcs-issuer apply -f adcs-issuer-all.yaml --dry-run=server


kubectl -n adcs-issuer get pod 

kubectl -n adcs-issuer logs deploy/adcs-issuer-controller-manager

kubectl -n adcs-issuer logs deploy/adcs-sim-deployment


kubectl -n adcs-issuer delete -f adcs-issuer-all.yaml

