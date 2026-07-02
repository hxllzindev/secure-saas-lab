# Runbook

## Subir a stack

```bash
TOKEN_SECRET="$(openssl rand -base64 48)" docker compose up -d --build
docker compose ps
```

## Verificar

```bash
node scripts/verify-stack.mjs
curl http://127.0.0.1:3000/api/health
```

## Logs

```bash
docker compose logs -f app
docker compose logs -f database
```

## Reiniciar apenas a aplicacao

```bash
docker compose up -d --build --force-recreate app
```

## Resetar os dados de laboratorio

Esta operacao remove o volume PostgreSQL local:

```bash
docker compose down -v
docker compose up -d --build
```

## Confirmar RLS manualmente

```bash
docker compose exec database psql \
  postgresql://aegis_app:aegis_app_dev@127.0.0.1:5432/secure_saas
```

```sql
BEGIN;
SELECT set_config('app.tenant_id', 'acme', true);
SELECT * FROM invoices WHERE tenant_id = 'orbit';
COMMIT;
```

Resultado esperado: zero linhas.

## Problemas comuns

### Porta 3000 ocupada

Pare o processo anterior ou altere o mapeamento em `compose.yaml`.

### Mudancas nas migrations nao aparecem

Scripts em `/docker-entrypoint-initdb.d` rodam apenas na criacao do volume. Em desenvolvimento, execute o reset de dados.

### Login falha apos recriar a aplicacao

Confirme que `TOKEN_SECRET` permanece igual entre reinicios e limpe cookies antigos caso tenha mudado.

## Checklist antes de publicar

- Substituir credenciais de banco locais por secret manager
- Usar TLS no proxy de entrada
- Migrar MFA para TOTP ou WebAuthn
- Mover rate limiting e sessoes para infraestrutura distribuida quando houver replicas
- Desabilitar ou separar fisicamente o modo vulneravel
- Configurar backups, retencao de logs e alertas
