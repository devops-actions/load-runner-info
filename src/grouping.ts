interface group {
  name: string
  counter: number
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function groupRunnersByLabel(runnersJson: any): group[] {
  const groups: group[] = []
  runnersJson.runners.forEach((runner: any) => {
        runner.labels.forEach((label: any) => {
            const index = groups.findIndex((g: any) => g.name === label.name)            
            if (index > -1) {
                // existing group                
                groups[index].counter = groups[index].counter + 1
            }
            else {
                // new group
                groups.push({name: label.name, counter: 1})
            }
    })
  })
  return groups
}
