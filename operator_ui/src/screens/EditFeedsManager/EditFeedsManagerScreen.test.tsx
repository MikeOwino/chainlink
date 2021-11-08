import * as React from 'react'

import { Route } from 'react-router-dom'
import {
  renderWithRouter,
  screen,
  waitForElementToBeRemoved,
} from 'support/test-utils'
import userEvent from '@testing-library/user-event'
import { MockedProvider, MockedResponse } from '@apollo/client/testing'

import { buildFeedsManager } from 'support/factories/feedsManager'
import {
  UPDATE_FEEDS_MANAGER_MUTATION,
  EditFeedsManagerScreen,
} from './EditFeedsManagerScreen'
import { FEEDS_MANAGERS_QUERY } from 'src/hooks/useFeedsManagersQuery'
import Notifications from 'pages/Notifications'

const { findByText, findByTestId, getByRole, queryByRole } = screen

function renderComponent(mocks: MockedResponse[]) {
  renderWithRouter(
    <>
      <Notifications />
      <Route exact path="/">
        <MockedProvider mocks={mocks} addTypename={false}>
          <EditFeedsManagerScreen />
        </MockedProvider>
      </Route>

      <Route exact path="/feeds_manager/new">
        New Redirect Success
      </Route>
      <Route exact path="/feeds_manager">
        Root Redirect Success
      </Route>
    </>,
  )
}

it('renders the page', async () => {
  const mocks: MockedResponse[] = [
    {
      request: {
        query: FEEDS_MANAGERS_QUERY,
      },
      result: {
        data: {
          feedsManagers: {
            results: [buildFeedsManager()],
          },
        },
      },
    },
  ]

  renderComponent(mocks)

  await waitForElementToBeRemoved(() => queryByRole('progressbar'))

  expect(await findByText('Edit Feeds Manager')).toBeInTheDocument()
  expect(await findByTestId('feeds-manager-form')).toBeInTheDocument()
})

it('redirects when a manager does not exist', async () => {
  const mocks: MockedResponse[] = [
    {
      request: {
        query: FEEDS_MANAGERS_QUERY,
      },
      result: {
        data: {
          feedsManagers: {
            results: [],
          },
        },
      },
    },
  ]

  renderComponent(mocks)

  await waitForElementToBeRemoved(() => queryByRole('progressbar'))

  expect(await findByText('New Redirect Success')).toBeInTheDocument()
})

it('submits the form', async () => {
  const mgr = buildFeedsManager()

  const mocks: MockedResponse[] = [
    {
      request: {
        query: FEEDS_MANAGERS_QUERY,
      },
      result: {
        data: {
          feedsManagers: {
            results: [mgr],
          },
        },
      },
    },
    {
      request: {
        query: UPDATE_FEEDS_MANAGER_MUTATION,
        variables: {
          id: mgr.id,
          input: {
            name: 'updated',
            uri: 'localhost:80812',
            publicKey: '22222',
            jobTypes: ['FLUX_MONITOR', 'OCR'],
            isBootstrapPeer: false,
            bootstrapPeerMultiaddr: undefined,
          },
        },
      },
      result: {
        data: {
          updateFeedsManager: {
            __typename: 'UpdateFeedsManagerSuccess',
            feedsManager: buildFeedsManager({
              name: 'updated',
              uri: 'localhost:80812',
              publicKey: '22222',
              jobTypes: ['FLUX_MONITOR', 'OCR'],
            }),
          },
        },
      },
    },
    {
      request: {
        query: FEEDS_MANAGERS_QUERY,
      },
      result: {
        data: {
          feedsManagers: {
            results: [
              buildFeedsManager({
                name: 'updated',
                uri: 'localhost:80812',
                publicKey: '22222',
                jobTypes: ['FLUX_MONITOR', 'OCR'],
              }),
            ],
          },
        },
      },
    },
  ]

  renderComponent(mocks)

  await waitForElementToBeRemoved(() => queryByRole('progressbar'))

  const nameInput = getByRole('textbox', { name: 'Name *' })
  userEvent.clear(nameInput)
  userEvent.type(nameInput, 'updated')

  const uriInput = getByRole('textbox', { name: 'URI *' })
  userEvent.clear(uriInput)
  userEvent.type(uriInput, 'localhost:80812')

  const publicKeyInput = getByRole('textbox', { name: 'Public Key *' })
  userEvent.clear(publicKeyInput)
  userEvent.type(publicKeyInput, '22222')

  userEvent.click(getByRole('checkbox', { name: /ocr/i }))

  userEvent.click(getByRole('button', { name: /submit/i }))

  expect(await findByText('Feeds Manager Updated')).toBeInTheDocument()
  expect(await findByText('Root Redirect Success')).toBeInTheDocument()
})

it('handles a not found error', async () => {
  const mgr = buildFeedsManager()

  const mocks: MockedResponse[] = [
    {
      request: {
        query: FEEDS_MANAGERS_QUERY,
      },
      result: {
        data: {
          feedsManagers: {
            results: [mgr],
          },
        },
      },
    },
    {
      request: {
        query: UPDATE_FEEDS_MANAGER_MUTATION,
        variables: {
          id: mgr.id,
          input: {
            name: mgr.name,
            uri: mgr.uri,
            publicKey: mgr.publicKey,
            jobTypes: ['FLUX_MONITOR'],
            isBootstrapPeer: false,
            bootstrapPeerMultiaddr: undefined,
          },
        },
      },
      result: {
        data: {
          updateFeedsManager: {
            __typename: 'NotFoundError',
            code: 'NOT_FOUND',
            message: 'feeds manager not found',
          },
        },
      },
    },
  ]

  renderComponent(mocks)

  await waitForElementToBeRemoved(() => queryByRole('progressbar'))

  userEvent.click(getByRole('button', { name: /submit/i }))

  expect(await findByText('feeds manager not found')).toBeInTheDocument()
})

it('handles a input errors', async () => {
  const mgr = buildFeedsManager()

  const mocks: MockedResponse[] = [
    {
      request: {
        query: FEEDS_MANAGERS_QUERY,
      },
      result: {
        data: {
          feedsManagers: {
            results: [mgr],
          },
        },
      },
    },
    {
      request: {
        query: UPDATE_FEEDS_MANAGER_MUTATION,
        variables: {
          id: mgr.id,
          input: {
            name: mgr.name,
            uri: mgr.uri,
            publicKey: mgr.publicKey,
            jobTypes: ['FLUX_MONITOR'],
            isBootstrapPeer: false,
            bootstrapPeerMultiaddr: undefined,
          },
        },
      },
      result: {
        data: {
          updateFeedsManager: {
            __typename: 'InputErrors',
            errors: [
              {
                code: 'INPUT_ERROR',
                message: 'invalid hex value',
                path: 'input/publicKey',
              },
            ],
          },
        },
      },
    },
  ]

  renderComponent(mocks)

  await waitForElementToBeRemoved(() => queryByRole('progressbar'))

  userEvent.click(getByRole('button', { name: /submit/i }))

  expect(await findByText('Invalid Input')).toBeInTheDocument()
  expect(await findByTestId('publicKey-helper-text')).toHaveTextContent(
    'invalid hex value',
  )
})
