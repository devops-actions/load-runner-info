# load-runner-info
Load the information for the runners that are available for the organization or the repository, including status checks.
Can be used to verify the amount of runners for a label is as expected.

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/devops-actions/load-runner-info/badge)](https://api.securityscorecards.dev/projects/github.com/devops-actions/load-runner-info)

# Example
Basic usage:
``` yaml
      - uses: devops-actions/load-runner-info@v1.0.6
        id: load-runner-info-org
        with: 
          accessToken: ${{ secrets.access_token }}
          organization: ${{ env.organization }}
```
Read the complete example for using the outputs as well.

## Inputs

|Name|Type|Description|
|---|---|---|
|`organization`|string|The slug of the organization to load the runners from|
|`repo`|string|The slug of the repo to load the runners from, `organization` required as well|
|`accessToken`|string|The access token to use to connect to the GitHub API|

### Access token information
To run this action at the **organization** level, the access token must have scope `admin:org` (PAT) or `org:Self-hosted runners` (GitHub App).
To run this action at the **repository** level, the access token must have scope `owner:repo`

## Outputs

|Name|Type|Description|
|---|---|---|
|`runners`|string|A JSON string with the runner information available|
|`grouped`|string|A JSON string with the number of runner grouped by their labels, also indicating their status|

When there are so many runners the JSON gets to large to use, use the filebased outputs instead:
|Name|Type|Description|
|---|---|---|
|`runners-file-location`|string|The path to the file with the runner information available|
|`grouped-file-location`|string|The path to the file with the number of runners grouped by their labels, also indicating their status|

Runners output example:
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

Grouped output example:
``` json
[
  { "name": "self-hosted", "counter": 1, "status": 1 },
  { "name": "Windows", "counter": 1, "status": 1 },
  { "name": "X64", "counter": 1, "status": 1 }
]
```
##### Note: status indicates the number of the runners that is online for that label.   



# Full usage example
Below is an example how I use this action to load the information on the available runners as well as test if there are enough runners online (see step `Test runner info`).
``` yaml
jobs:
  test-from-organization:
    runs-on: ubuntu-latest
    steps:
      - name: Get access token
        id: get_workflow_token
        uses: peter-murray/workflow-application-token-action@v2.1.0
        with:
          application_id: ${{ secrets.APPLICATION_ID }}
          application_private_key: ${{ secrets.APPLICATION_PRIVATE_KEY }}
          
      - uses: devops-actions/load-runner-info@v1.0.6
        id: load-runner-info-org
        with: 
          accessToken: ${{ steps.get_workflow_token.outputs.token }}
          organization: ${{ env.organization }}

      - name: Upload result file as artefact for inspection
        uses: actions/upload-artifact@v2
        with: 
          name: runners-organization-${{ env.organization }}
          path: 
            - ${{ steps.load-runner-info-org.outputs.runners-file-location }}
            - ${{ steps.load-runner-info-org.outputs.grouped-file-location }}

      - uses: actions/github-script@v5
        name: Test runner info
        with: 
          script: |
            const info = JSON.parse(`${{ steps.load-runner-info-org.outputs.runners-file-location }}`)
            if (info.length == 0) {
              core.error('No runners found')            
              return
            }
            
            console.log(`Found [${info.runners.length}] runner(s)`)
            for (let num = 0; num < info.runners.length; num++) {
              const runner = info.runners[num]
              console.log(`- name: [${runner.name}]`)
            }

            console.log(``)

            const grouped = JSON.parse(`${{ steps.load-runner-info-org.outputs.grouped-file-location }}`)
            console.log(`Found ${grouped.length} runner label(s)`)
            for (let num = 0; num < grouped.length; num++) {
              const group = grouped[num]
              console.log(`- label: [${group.name}], runner with this label: [${group.counter}] with [${group.status}] online runners`)
            }

            // example of a test you can do on the amount of runners online with this label
            const selfHosted = grouped.find(group => group.name === 'self-hosted')
            if (selfHosted.status > 10) {
              core.error(`Too many runners with label "self-hosted" found`)
              return
            }

            // example of a test you can do on the amount of runners online with this label
            if (selfHosted.status < selfHosted.counter) {
              core.error(`There are [${selfHosted.counter - selfHosted.status}] runners offline`)
              return
            }
```
