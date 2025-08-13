start the server
```bash
vault server -dev
```

create a vault role
```bash
vault write auth/approle/role/my-role \
    token_policies="default,web-app" \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_ttl=24h \
    secret_id_num_uses=10

```

retrieve the role id 
```
vault read auth/approle/role/my-role/role-id
```
(or) 

for automation
```bash
vault read -format=json auth/approle/role/my-role/role-id \
  | jq -r .data.role_id

```
get the secret id
```bash
vault write -f auth/approle/role/my-role/secret-id

```
login with approle 
```bash
vault write auth/approle/login \
    role_id="192e9220-f35c-c2e9-2931-464696e0ff24" \
    secret_id="4e46a226-fdd5-5ed1-f7bb-7b92a0013cad"
```

write and attach policy for the approle 

```bash
vault policy write db-policy ./db-policy.hcl
```
```bash
vault write auth/approle/role/my-role \
    token_policies="db-policy" 
```

set and get the kv secrets 
```bash
vault kv put secret/database/mysql \
    root_password=admin \
    user_password=admin
```

```bash
vault kv get secret/database/mysql 
```

---
debug the plugin 

```bash
sudo journalctl -u docker.service -f \
  | grep plugin_id
```
or

```bash
sudo journalctl -u docker.service -f | grep "$(docker plugin ls --format 
'{{.ID}}')"
```
