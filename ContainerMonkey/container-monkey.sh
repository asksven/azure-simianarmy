#!/bin/bash

containers=$(sudo docker image list | awk '{if(NR>1) print $1}')
#containers=("linuxserver/couchpotato" "linuxserver/sabnzbd" "plexinc/pms-docker")

echo "Analysing ${containers[*]}"

SLACK_URL="https://functions-slack.azurewebsites.net/api/SlackBot?code=r0c705ab3q8ec1h86qjmwkrugbqepbrf"
SLACK_CHANNEL="#testing"

# initialize arrays
stops=()
warns=()

# loop through all containers
for container in $containers #"${containers[@]}"
do
  echo "Container: $container"
  sudo docker exec anchore_cli anchore analyze --image $container
  sudo docker exec anchore_cli anchore gate --image $container

  # return codes from 'anchore gate': https://github.com/anchore/anchore/wiki/Gates

  # return code will be 1 if anchore gate returns STOP
  case $? in
  1)
    echo ">>>vulnerabilities detected"
    stops+=("$container")
    echo "Stops: ${stops[*]}"
    ;;
  2)
    echo ">>>warnings detected"
    warns+=("$container")
    echo "Warnings: ${warns[*]}"
    ;;
  esac

  echo ================================
done



if [ ! -z "$SLACK_URL" ]; then
  echo "processing errors...."
  body="{ \"channel\": \"${SLACK_CHANNEL}\", \"username\": \"ContainerMonkey\", \"text\": \"Update from `date`\", \"icon_url\": \"\", \"icon_emoji\": \":cop:\", \"fallback\": \"Upgrade your client\", \"notifications\": ["

  # now we add status info
  body+="{ \"type\": \"info\", \"title\": \"Summary\", \"text\": \"Scanned all images on host\" },"


  for stop in "${stops[@]}" #$stops
  do
        body+="{ \"type\": \"error\", \"title\": \"Vulnerabilty\", \"text\": \"$stop\"},"
  done

  for warn in "${warns[@]}" #r$warns
  do
        body+="{ \"type\": \"warn\", \"title\": \"Warning\", \"text\": \"$warn\"},"
  done


  body+="]}"

  echo payload: $body

  curl -i -X POST -H "Content-Type:application/json" $SLACK_URL --data "$body"
fi

