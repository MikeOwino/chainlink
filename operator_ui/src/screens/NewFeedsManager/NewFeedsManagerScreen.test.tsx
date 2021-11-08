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
import { FEEDS_MANAGERS_QUERY } from 'src/hooks/useFeedsManagersQuery'
import {
  CREATE_FEEDS_MANAGER_MUTATION,
  NewFeedsManagerScreen,
} from './NewFeedsManagerScreen'
import Notifications from 'pages/Notifications'

const { findByTestId, findByText, getByRole } = screen

function renderComponent(mocks: MockedResponse[]) {
  renderWithRouter(
    <>
      <Notifications />
      <Route exact path="/">
        <MockedProvider mocks={mocks} addTypename={false}>
          <NewFeedsManagerScreen />
        </MockedProvider>
      </Route>

      <Route path="/feeds_manager">Redirect Success</Route>
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
            results: [],
          },
        },
      },
    },
  ]

  renderComponent(mocks)

  await waitForElementToBeRemoved(() => screen.queryByRole('progressbar'))

  expect(await findByText('Register Feeds Manager')).toBeInTheDocument()
  expect(await findByTestId('feeds-manager-form')).toBeInTheDocument()
})

it('redirects when a manager exists', async () => {
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

  await waitForElementToBeRemoved(() => screen.queryByRole('progressbar'))

  expect(await findByText('Redirect Success')).toBeInTheDocument()
})

it('submits the form', async () => {
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
    {
      request: {
        query: CREATE_FEEDS_MANAGER_MUTATION,
        variables: {
          input: {
            name: 'Chainlink Feeds Manager',
            uri: 'localhost:8080',
            publicKey: '1111',
            jobTypes: ['FLUX_MONITOR'],
            isBootstrapPeer: false,
            bootstrapPeerMultiaddr: undefined,
          },
        },
      },
      result: {
        data: {
          createFeedsManager: {
            __typename: 'CreateFeedsManagerSuccess',
            feedsManager: buildFeedsManager(),
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
            results: [buildFeedsManager()],
          },
        },
      },
    },
  ]

  renderComponent(mocks)

  await waitForElementToBeRemoved(() => screen.queryByRole('progressbar'))

  // Note: The name input has a default value so we don't have to set it
  userEvent.type(getByRole('textbox', { name: 'URI *' }), 'localhost:8080')
  userEvent.type(getByRole('textbox', { name: 'Public Key *' }), '1111')
  userEvent.click(getByRole('checkbox', { name: 'Flux Monitor' }))

  userEvent.click(getByRole('button', { name: /submit/i }))

  expect(await findByText('Feeds Manager Created')).toBeInTheDocument()
  expect(await findByText('Redirect Success')).toBeInTheDocument()
})

it('handles input errors', async () => {
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
    {
      request: {
        query: CREATE_FEEDS_MANAGER_MUTATION,
        variables: {
          input: {
            name: 'Chainlink Feeds Manager',
            uri: 'localhost:8080',
            publicKey: '1111',
            jobTypes: ['FLUX_MONITOR'],
            isBootstrapPeer: false,
            bootstrapPeerMultiaddr: undefined,
          },
        },
      },
      result: {
        data: {
          createFeedsManager: {
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

  await waitForElementToBeRemoved(() => screen.queryByRole('progressbar'))

  // Note: The name input has a default value so we don't have to set it
  userEvent.type(getByRole('textbox', { name: 'URI *' }), 'localhost:8080')
  userEvent.type(getByRole('textbox', { name: 'Public Key *' }), '1111')
  userEvent.click(getByRole('checkbox', { name: 'Flux Monitor' }))

  userEvent.click(getByRole('button', { name: /submit/i }))

  expect(await findByText('Invalid Input')).toBeInTheDocument()
  expect(await findByTestId('publicKey-helper-text')).toHaveTextContent(
    'invalid hex value',
  )
})
