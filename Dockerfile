FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY Directory.Build.props NuGet.config ./
COPY src/VeriRandomSyncRelay.Crypto/VeriRandomSyncRelay.Crypto.csproj src/VeriRandomSyncRelay.Crypto/
COPY src/VeriRandomSyncRelay.Server/VeriRandomSyncRelay.Server.csproj src/VeriRandomSyncRelay.Server/
RUN dotnet restore src/VeriRandomSyncRelay.Server/VeriRandomSyncRelay.Server.csproj

COPY src/VeriRandomSyncRelay.Crypto/ src/VeriRandomSyncRelay.Crypto/
COPY src/VeriRandomSyncRelay.Server/ src/VeriRandomSyncRelay.Server/
RUN dotnet publish src/VeriRandomSyncRelay.Server/VeriRandomSyncRelay.Server.csproj \
    -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app ./
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
ENTRYPOINT ["dotnet", "VeriRandomSyncRelay.Server.dll"]
