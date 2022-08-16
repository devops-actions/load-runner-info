import {expect, test} from '@jest/globals'
import { groupRunnersByLabel } from '../src/grouping'

const singleRunnerData = JSON.parse(`{
    [
        {
            "id": 2,
            "name": "ROB-XPS9700",
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
    }`)

    const twoRunnerData = JSON.parse(`{
        [
            {
                "id": 1,
                "name": "ROB-XPS9700-1",
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
                },
                {
                    "id": 2,
                    "name": "ROB-XPS9700-2",
                    "os": "windows",
                    "status": "offline",
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
                        },
                        {
                            "id": 4,
                            "name": "Test",
                            "type": "read-only"
                        }
                        ]
                    }
            ]
        }`)

test('grouping singleRunnerData returns 3 groups with a single counter each', () => {
    const groups = groupRunnersByLabel(singleRunnerData)
    expect(Object.keys(groups).length).toBe(3)
    // and each group has a counter of 1
    groups.forEach((group: any) => {
        expect(group.counter).toBe(1)
    })
})

test('grouping twoRunnerData returns 4 groups with correct counter each', () => {
    const groups = groupRunnersByLabel(twoRunnerData)
    expect(Object.keys(groups).length).toBe(4)

    const selfHostedGroup = groups.find((g: any) => g.name === 'self-hosted')
    expect(selfHostedGroup).toBeDefined()
    if (selfHostedGroup){
        expect(selfHostedGroup.counter).toBe(2)
        expect(selfHostedGroup.status).toBe(1)
    }

    const windowsGroup = groups.find((g: any) => g.name === 'Windows')
    expect(windowsGroup).toBeDefined()
    if (windowsGroup){
        expect(windowsGroup.counter).toBe(2)
        expect(windowsGroup.status).toBe(1)
    }

    const bitnessGroup = groups.find((g: any) => g.name === 'X64')
    expect(bitnessGroup).toBeDefined()
    if (bitnessGroup){
        expect(bitnessGroup.counter).toBe(2)
        expect(bitnessGroup.status).toBe(1)
    }

    const testGroup = groups.find((g: any) => g.name === 'Test')
    expect(testGroup).toBeDefined()
    if (testGroup){
        expect(testGroup.counter).toBe(1)
        expect(testGroup.status).toBe(0)
    }
})
