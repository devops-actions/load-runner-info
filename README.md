# load-runner-info
Load the information for the runners that are available

## Inputs

|Name|Type|Description|
|---|---|---|
|`organization`|string|The slug of the organization to load the runners from|
|`repo`|string|The slug of the repo to load the runners from, `organization` required as well|
|`accessToken`|string|The access token to use to connect to the GitHub API|

### Access token information
To run this action at the **organization** level, the access token must have scope `admin:org`
To run this action at the **repository** level, the access token must have scope `owner:repo`

## Outputs

|Name|Type|Description|
|---|---|---|
|`runners`|string|A JSON string with the runner information available|

Example:
``` json
{
    "total_count": 1,
    "runners": [
        {
            "id": 2,
            "name": "my-runner",
            "os": "windows",
            "status": "online",
            "busy": false,
            "labels": [
                {
                    "id": 1,
                    "name": "self-hosted",
                    "type": "read-only"
                },
                {
                    "id": 2,
                    "name": "Windows",
                    "type": "read-only"
                },
                {
                    "id": 3,
                    "name": "X64",
                    "type": "read-only"
                }
            ]
        }
    ]
}
```