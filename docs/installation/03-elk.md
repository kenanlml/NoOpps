# Installation d'Elasticsearch et Kibana

## 1. Docker

Installation depuis le dépôt officiel Docker (le paquet `docker.io` d'Ubuntu ne fournit pas toujours le plugin compose v2).

```bash
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu resolute stable" | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker kenan
```

Il faut se reconnecter pour que l'appartenance au groupe `docker` soit prise en compte.

Vérification :

```bash
docker --version          # Docker version 29.9.0
docker compose version    # Docker Compose version v5.6.0
docker run --rm hello-world
```

### vm.max_map_count

Elasticsearch exige `vm.max_map_count >= 262144`. Ubuntu 26.04 le fixe déjà à 1048576 par défaut, donc aucun fichier sysctl n'est ajouté.

```bash
sysctl vm.max_map_count   # vm.max_map_count = 1048576
```
