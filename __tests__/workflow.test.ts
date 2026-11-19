import {expect, test} from '@jest/globals'
import fs from 'fs'
import yaml from 'js-yaml'
import path from 'path'

test('publishing workflow releases with SBOMs and attestations', () => {
  const workflowPath = path.resolve('.github/workflows/publishing.yml')
  expect(fs.existsSync(workflowPath)).toBe(true)

  const workflowContent = fs.readFileSync(workflowPath, 'utf8')
  const workflow = yaml.load(workflowContent) as any

  expect(workflow).toBeDefined()
  expect(workflow.jobs).toBeDefined()

  // The release (with SBOMs and artifact attestations) is created by the shared
  // reusable workflow in devops-actions/.github, pinned to a commit SHA
  const releaseJob = workflow.jobs.release
  expect(releaseJob).toBeDefined()
  expect(releaseJob.uses).toMatch(
    /^devops-actions\/\.github\/\.github\/workflows\/rw-release-attestation\.yml@[0-9a-f]{40}$/
  )

  // The reusable workflow needs these permissions to create, sign and store the attestations
  expect(releaseJob.permissions).toEqual({
    contents: 'write',
    'id-token': 'write',
    attestations: 'write'
  })

  // Only release after the build and the action tests passed
  expect(workflow.jobs.build).toBeDefined()
  expect(releaseJob.needs).toBe('build')
})

test('check-for-release workflow provisions labels before creating a release issue', () => {
  const workflowPath = path.resolve('.github/workflows/check-for-release.yml')
  expect(fs.existsSync(workflowPath)).toBe(true)

  const workflowContent = fs.readFileSync(workflowPath, 'utf8')
  const workflow = yaml.load(workflowContent) as any

  expect(workflow).toBeDefined()
  expect(workflow.jobs).toBeDefined()
  expect(workflow.jobs['check-time-for-new-release']).toBeDefined()

  const checkJob = workflow.jobs['check-time-for-new-release']
  expect(checkJob.steps).toBeDefined()

  const releaseIssueStep = checkJob.steps.find(
    (step: any) => step.name === 'Create release issue'
  )

  expect(releaseIssueStep).toBeDefined()
  expect(releaseIssueStep.run).toContain('gh label list --limit 200 --json name')
  expect(releaseIssueStep.run).toContain('Name = "release"')
  expect(releaseIssueStep.run).toContain('Name = "automated"')
  expect(releaseIssueStep.run).toContain('Name = "security"')
  expect(releaseIssueStep.run).toContain('& gh label create')
  expect(releaseIssueStep.run).toContain('--body-file')
  expect(releaseIssueStep.run).not.toContain('Invoke-Expression')
})
