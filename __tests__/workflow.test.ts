import {expect, test} from '@jest/globals'
import fs from 'fs'
import yaml from 'js-yaml'
import path from 'path'

test('publishing workflow includes SBOM generation', () => {
  const workflowPath = path.resolve('.github/workflows/publishing.yml')
  expect(fs.existsSync(workflowPath)).toBe(true)
  
  const workflowContent = fs.readFileSync(workflowPath, 'utf8')
  const workflow = yaml.load(workflowContent) as any
  
  expect(workflow).toBeDefined()
  expect(workflow.jobs).toBeDefined()
  expect(workflow.jobs.publish).toBeDefined()
  
  const publishJob = workflow.jobs.publish
  expect(publishJob.steps).toBeDefined()
  
  // Check that SBOM generation step exists
  const sbomStep = publishJob.steps.find((step: any) => 
    step.name && step.name.includes('Generate SBOM')
  )
  expect(sbomStep).toBeDefined()
  expect(sbomStep.run).toContain('gh api')
  expect(sbomStep.run).toContain('dependency-graph/sbom')
  
  // Check that release step includes SBOM file
  const releaseStep = publishJob.steps.find((step: any) => 
    step.uses && step.uses.includes('action-gh-release')
  )
  expect(releaseStep).toBeDefined()
  expect(releaseStep.with.files).toContain('sbom.spdx.json')
  expect(releaseStep.with.body).toContain('SBOM')
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
