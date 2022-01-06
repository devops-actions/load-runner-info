interface group {
  name: string
  counter: number
  status: number
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function groupRunnersByLabel(runnersJson: any): group[] {
  const groups: group[] = []
  runnersJson.runners.forEach((runner: any) => {
        runner.labels.forEach((label: any) => {
            const index = groups.findIndex((g: any) => g.name === label.name)
            const status = runner.status === 'online' ? 1 : 0
            if (index > -1) {
                // existing group                
                groups[index].counter = groups[index].counter + 1
                groups[index].status = groups[index].status + status
            }
            else {
                // new group
                groups.push({name: label.name, counter: 1, status: status})
            }
    })
  })
  return groups
}
