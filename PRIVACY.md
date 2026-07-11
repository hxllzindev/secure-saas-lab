# Privacidade e LGPD

Secure SaaS Lab usa apenas pessoas, empresas, credenciais e faturas fictícias mantidas em memória. O laboratório não deve receber dados pessoais reais, especialmente no modo vulnerável.

## Minimização

- Não insira nome, e-mail, CPF, endereço, credencial real, dado financeiro ou dado pessoal sensível.
- Use somente os registros fictícios incluídos no seed.
- O armazenamento em memória é descartado ao encerrar o processo; logs e evidências de CI também devem permanecer sanitizados.
- O frontend público não contém credenciais e não recebe nomes, emails, tenant IDs,
  clientes, valores financeiros exatos, autores/conteúdo de notas ou atores/recursos
  da auditoria. A interface recebe somente projeções sintéticas allowlisted.

## Requisitos antes de uso real

Uma versão real precisaria documentar controlador, finalidade e base legal; separar tenants em persistência durável; aplicar identidade individual e autorização por objeto; definir retenção e descarte; manter trilha de acesso; proteger backups e segredos; e oferecer canal para exercício dos direitos do titular.

Em incidente com risco ou dano relevante, siga a Resolução CD/ANPD nº 15/2024, incluindo avaliação, registro, contenção e, quando aplicável, comunicação à ANPD e aos titulares em até três dias úteis. Registros do incidente devem ser preservados pelo prazo regulamentar.

## Referências oficiais

- LGPD: https://www2.camara.leg.br/legin/fed/lei/2018/lei-13709-14-agosto-2018-787077-normaatualizada-pl.html
- Direitos dos titulares: https://www.gov.br/anpd/pt-br/assuntos/titular-de-dados-1/direito-dos-titulares
- Guia de segurança para agentes de pequeno porte: https://www.gov.br/anpd/pt-br/centrais-de-conteudo/materiais-educativos-e-publicacoes/processo-guia-orientativo-sobre-seguranca-da-informacao-para-agentes-de-tratamento-de-pequeno-porte.pdf
