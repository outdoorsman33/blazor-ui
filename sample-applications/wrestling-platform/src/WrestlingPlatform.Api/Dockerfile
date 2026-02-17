FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY src/WrestlingPlatform.Domain/WrestlingPlatform.Domain.csproj src/WrestlingPlatform.Domain/
COPY src/WrestlingPlatform.Application/WrestlingPlatform.Application.csproj src/WrestlingPlatform.Application/
COPY src/WrestlingPlatform.Infrastructure/WrestlingPlatform.Infrastructure.csproj src/WrestlingPlatform.Infrastructure/
COPY src/WrestlingPlatform.Api/WrestlingPlatform.Api.csproj src/WrestlingPlatform.Api/

RUN dotnet restore src/WrestlingPlatform.Api/WrestlingPlatform.Api.csproj

COPY . .
WORKDIR /src/src/WrestlingPlatform.Api
RUN dotnet publish WrestlingPlatform.Api.csproj -c Release -o /app/publish /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app
COPY --from=build /app/publish .

ENV ASPNETCORE_URLS=http://+:10000
EXPOSE 10000

ENTRYPOINT ["dotnet", "WrestlingPlatform.Api.dll"]
