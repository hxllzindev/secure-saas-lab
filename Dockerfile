FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS build
WORKDIR /src
COPY SecureSaasLab.sln ./
COPY src/SecureSaasLab.Api/SecureSaasLab.Api.csproj src/SecureSaasLab.Api/
RUN dotnet restore src/SecureSaasLab.Api/SecureSaasLab.Api.csproj
COPY src/SecureSaasLab.Api src/SecureSaasLab.Api
RUN dotnet publish src/SecureSaasLab.Api/SecureSaasLab.Api.csproj -c Release -o /app/publish --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0-alpine
WORKDIR /app
RUN apk upgrade --no-cache \
    && addgroup -S aegis \
    && adduser -S -G aegis aegis
COPY --from=build --chown=aegis:aegis /app/publish .
ENV ASPNETCORE_ENVIRONMENT=Production
ENV ASPNETCORE_URLS=http://+:3000
USER aegis
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:3000/api/health || exit 1
ENTRYPOINT ["dotnet", "SecureSaasLab.Api.dll"]
