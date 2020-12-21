#!/bin/sh

run ()
{
    echo "dotnet run"
	cd JiraOauth
	dotnet run -c Release --launch-profile JiraOauth
}

docker ()
{
	echo "docker"
	docker-compose up
}

run & docker