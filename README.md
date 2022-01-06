# load-runner-info
Load the information for the runners that are available for the organization or the repository, including status checks.
Can be used to verify the amount of runners for a label is as expected.

# Example
Basic usage:
``` yaml
      - uses: devops-actions/load-runner-info@main
        id: load-runner-info-org
        with: 
          accessToken: ${{ secrets.PAT }}
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
      - uses: devops-actions/load-runner-info@main
        id: load-runner-info-org
        with: 
          accessToken: ${{ secrets.PAT }}
          organization: ${{ env.organization }}

      - name: Store output in result files
        run: |
          echo '${{ steps.load-runner-info-org.outputs.runners }}' > 'runners-organization.json'
          echo '${{ steps.load-runner-info-org.outputs.grouped }}' > 'runners-grouped-organization.json'
            
      - name: Upload result file as artefact for inspection
        uses: actions/upload-artifact@v2
        with: 
          name: runners-organization-${{ env.organization }}
          path: 'runners-**.json'

      - uses: actions/github-script@v5
        name: Test runner info
        with: 
          script: |
            const info = JSON.parse(`${{ steps.load-runner-info-org.outputs.runners }}`)
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

            const grouped = JSON.parse(`${{ steps.load-runner-info-org.outputs.grouped }}`)
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