# install docker

# Add Docker's official GPG key:
sudo apt-get update -y
sudo apt-get install ca-certificates curl -y
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo \
"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
$(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update -y

# apt install docker version 28.3.3
DOCKER_VERSION="5:28.3.3-1~debian.$(. /etc/os-release && echo "$VERSION_CODENAME")~$(dpkg --print-architecture)"
sudo apt-get install docker-ce=$DOCKER_VERSION docker-ce-cli=$DOCKER_VERSION containerd.io -y

# install docker compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.32.3/docker-compose-linux-x86_64" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

#install apache2
sudo apt-get install nginx -y

# Définir le chemin du fichier de configuration
CONFIG_FILE="/etc/nginx/conf.d/nextcloud.conf"

# Récupérer l'adresse IP publique
IP_ADDRESS=$(hostname -I | awk '{print $1}')

# Convertir l'IP en domaine inversé
IFS='.' read -r -a octets <<< "$IP_ADDRESS"
DOMAIN="${octets[3]}.${octets[2]}.${octets[1]}.${octets[0]}.rev.as200136.net"

# Créer le fichier de configuration avec le contenu fourni
cat <<EOF > "$CONFIG_FILE"
server {
	listen 80;
	listen [::]:80;
	root /var/www/html;
	server_name $DOMAIN;

	location / {
		proxy_pass http://localhost:11000;
		proxy_set_header Host \$host;
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		proxy_set_header X-Forwarded-Proto \$scheme;
		add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload";
		client_max_body_size 0;
	}

	location /.well-known/carddav {
	return 301 \$scheme://\$host/remote.php/dav;
	}

	location /.well-known/caldav {
	return 301 \$scheme://\$host/remote.php/dav;
	}
}
EOF

# Redémarrer Nginx pour appliquer la configuration
systemctl restart nginx

echo "Configuration Nginx pour Nextcloud créée avec succès dans $CONFIG_FILE"


sudo apt install -y certbot python3-certbot-nginx

certbot --nginx -d $DOMAIN -m qbdzqdyhgujq@gmail.com --agree-tos --non-interactive

# Remplacer le vhost
content=$(cat <<EOF
map \$http_upgrade \$connection_upgrade {
	default upgrade;
	'' close;
}

server {
	listen 80;
	listen [::]:80;            # comment to disable IPv6

	if (\$scheme = "http") {
		return 301 https://\$host\$request_uri;
	}
	if (\$http_x_forwarded_proto = "http") {
		return 301 https://\$host\$request_uri;
	}

	listen 443 ssl http2;      # for nginx versions below v1.25.1
	listen [::]:443 ssl http2; # for nginx versions below v1.25.1 - comment to disable IPv6

	# listen 443 ssl;      # for nginx v1.25.1+
	# listen [::]:443 ssl; # for nginx v1.25.1+ - keep comment to disable IPv6
	# http2 on;            # uncomment to enable HTTP/2 - supported on nginx v1.25.1+

	# listen 443 quic reuseport;       # uncomment to enable HTTP/3 / QUIC - supported on nginx v1.25.0+ - please remove "reuseport" if there is already another quic listener on port 443 with enabled reuseport
	# listen [::]:443 quic reuseport;  # uncomment to enable HTTP/3 / QUIC - supported on nginx v1.25.0+ - please remove "reuseport" if there is already another quic listener on port 443 with enabled reuseport - keep comment to disable IPv6
	# http3 on;                                 # uncomment to enable HTTP/3 / QUIC - supported on nginx v1.25.0+
	# quic_gso on;                              # uncomment to enable HTTP/3 / QUIC - supported on nginx v1.25.0+
	# quic_retry on;                            # uncomment to enable HTTP/3 / QUIC - supported on nginx v1.25.0+
	# quic_bpf on;                              # improves  HTTP/3 / QUIC - supported on nginx v1.25.0+, if nginx runs as a docker container you need to give it privileged permission to use this option
	# add_header Alt-Svc 'h3=":443"; ma=86400'; # uncomment to enable HTTP/3 / QUIC - supported on nginx v1.25.0+

	proxy_buffering off;
	proxy_request_buffering off;

	client_max_body_size 0;
	client_body_buffer_size 512k;
	# http3_stream_buffer_size 512k; # uncomment to enable HTTP/3 / QUIC - supported on nginx v1.25.0+
	proxy_read_timeout 86400s;

	server_name $DOMAIN;

	location / {
		proxy_pass http://127.0.0.1:11000\$request_uri; # Adjust to match APACHE_PORT and APACHE_IP_BINDING. See https://github.com/nextcloud/all-in-one/blob/main/reverse-proxy.md#adapting-the-sample-web-server-configurations-below

		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		proxy_set_header X-Forwarded-Port \$server_port;
		proxy_set_header X-Forwarded-Scheme \$scheme;
		proxy_set_header X-Forwarded-Proto \$scheme;
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header Host \$host;
		proxy_set_header Early-Data \$ssl_early_data;

		# Websocket
		proxy_http_version 1.1;
		proxy_set_header Upgrade \$http_upgrade;
		proxy_set_header Connection \$connection_upgrade;
	}

	# If running nginx on a subdomain (eg. nextcloud.example.com) of a domain that already has an wildcard ssl certificate from certbot on this machine,
	# the <your-nc-domain> in the below lines should be replaced with just the domain (eg. example.com), not the subdomain.
	# In this case the subdomain should already be secured without additional actions
	ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;   # managed by certbot on host machine
	ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem; # managed by certbot on host machine

	ssl_dhparam /etc/dhparam; # curl -L https://ssl-config.mozilla.org/ffdhe2048.txt -o /etc/dhparam

	ssl_early_data on;
	ssl_session_timeout 1d;
	ssl_session_cache shared:SSL:10m;

	ssl_protocols TLSv1.2 TLSv1.3;
	ssl_ecdh_curve x25519:x448:secp521r1:secp384r1:secp256r1;

	ssl_prefer_server_ciphers on;
	ssl_conf_command Options PrioritizeChaCha;
	ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256;
}
EOF
)

# Write the content to a file
echo "$content" > /etc/nginx/conf.d/nextcloud.conf

curl -L https://ssl-config.mozilla.org/ffdhe2048.txt -o /etc/dhparam

systemctl restart nginx
systemctl stop sshd


echo "--------------------------------"
echo "Installation terminée"
echo "--------------------------------"

