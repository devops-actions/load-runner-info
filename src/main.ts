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

    const octokit = new Octokit({auth: accessToken})

    let runnerInfo: any = {}
    if (organization !== '' && repo === '') {
      try {
        console.log(`Loading all runners from organization [${organization}]`)
        const { data } = await octokit.request("GET /orgs/{owner}/actions/runners", {
          owner: organization
        })

        console.log(`Found ${data.total_count} runners at the org level`)
        runnerInfo = data
      } catch (error) {
        console.log(error)
        core.setFailed(
          `Could not authenticate with PAT. Please check that it is correct and that it has [read access] to the organization or user account: ${error}`
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
          `Could not authenticate with PAT. Please check that it is correct and that it has [read access] to the organization or user account: ${error}`
        )
        return
      }
    }

    console.log(`Found ${runnerInfo.total_count} runners`)
    const json = JSON.stringify(runnerInfo)
    core.setOutput('runners', json)

    const grouped = groupRunnersByLabel(runnerInfo)
    console.log(`Found ${grouped.length} groups`)
    const jsonGrouped = JSON.stringify(grouped)
    core.setOutput('grouped', jsonGrouped)
}

run()