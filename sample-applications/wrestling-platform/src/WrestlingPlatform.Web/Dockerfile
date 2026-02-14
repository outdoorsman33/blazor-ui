# syntax=docker/dockerfile:1
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY src/WrestlingPlatform.Domain/WrestlingPlatform.Domain.csproj src/WrestlingPlatform.Domain/
COPY src/WrestlingPlatform.Application/WrestlingPlatform.Application.csproj src/WrestlingPlatform.Application/
COPY src/WrestlingPlatform.Web/WrestlingPlatform.Web.csproj src/WrestlingPlatform.Web/

RUN dotnet restore src/WrestlingPlatform.Web/WrestlingPlatform.Web.csproj

COPY . .
WORKDIR /src/src/WrestlingPlatform.Web
RUN dotnet publish WrestlingPlatform.Web.csproj -c Release -o /app/publish /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app
COPY --from=build /app/publish .

ENV ASPNETCORE_URLS=http://+:10000
EXPOSE 10000

ENTRYPOINT ["dotnet", "WrestlingPlatform.Web.dll"]
