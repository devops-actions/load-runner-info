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