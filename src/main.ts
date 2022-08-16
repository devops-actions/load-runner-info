import * as core from '@actions/core'
import {Octokit} from 'octokit'
import dotenv from 'dotenv'
import { groupRunnersByLabel } from './grouping'

// always import the config
dotenv.config()

async function run(): Promise<void> {
  console.log('Starting')

  const accessToken = core.getInput('accessToken') || process.env.ACCESS_TOKEN || ''
    const repo = core.getInput('repo') || process.env.GITHUB_REPO || ''
    const organization =
      core.getInput('organization') || process.env.GITHUB_ORGANIZATION || ''

    if (!accessToken || accessToken === '') {
      core.setFailed(
        "Parameter 'accessToken' is required to load all actions from the organization or user account"
      )
      return
    }

    if (organization === '') {
      core.setFailed(
        "Parameter 'organization' is required to load all runners from it. Please provide one of them."
      )
      return
    }

    const apiUrl = process.env.GITHUB_API_URL || 'https://api.github.com' 
    core.debug(`Using API URL: ${apiUrl}`)

    const octokit = new Octokit({auth: accessToken, baseUrl: apiUrl})

    let runnerInfo: any = {}
    if (organization !== '' && repo === '') {
      try {
        console.log(`Loading all runners from organization [${organization}]`)
       const data = await octokit.paginate("GET /orgs/{owner}/actions/runners", {
                                owner: organization
                              })

        if (data) {
          console.log(`Found ${data.total_count} runners at the org level`)
          runnerInfo = data
        }
      } catch (error) {
        console.log(error)
        core.setFailed(
          `Could not authenticate with access token. Please check that it is correct and that it has the correct scope (see readme) to the organization: ${error}`
        )
        return
      }
    }

    if (repo !== '') {
      try {
        console.log(`Loading all runners from repo [${organization}/${repo}]`)
        const { data } = await octokit.request("GET /repos/{owner}/{repo}/actions/runners", {
          owner: organization,
          repo
        })

        console.log(`Found ${data.total_count} runners at the repo level`)
        runnerInfo = data
      } catch (error) {
        console.log(error)
        core.setFailed(
          `Could not authenticate with access token. Please check that it is correct and that it has the correct scope (see readme) on the repository: ${error}`
        )
        return
      }
    }

    if (!runnerInfo) {
      core.setFailed(
        `Could not load any runners. Please check that the organization and repository are correct.`
      )
    }
    else {
      console.log(`Found ${runnerInfo.total_count} runners and loaded ${runnerInfo.runners.length} of them`)
      const json = JSON.stringify(runnerInfo)
      core.setOutput('runners', json)

      const grouped = groupRunnersByLabel(runnerInfo)
      console.log(`Found ${grouped.length} groups`)
      const jsonGrouped = JSON.stringify(grouped)
      core.setOutput('grouped', jsonGrouped)
    }
}

run()