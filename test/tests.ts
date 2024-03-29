import QUnit from 'qunit'
import 'qunit/qunit/qunit.css'
import { customAlphabet } from 'nanoid'
import { Auth, User } from '../src/index.js'

// @ts-ignore
window.HARNESS_RUN_END && QUnit.on('runEnd', window.HARNESS_RUN_END)

const apiKey = 'AIzaSyCnFgFqO3d7RbJDcNAp_eO21KSOISCP9IU'
const nanoid = customAlphabet('abcdefghijklmnopqrstuvwxyz', 16)
const domain = '1secmail.com'

const sleep = async (delayMS: number): Promise<void> =>
  new Promise(resolve => {
    setTimeout(resolve, delayMS)
  })

const decodeHTML = (html: string): string => {
  const txt = document.createElement('textarea')
  txt.innerHTML = html
  return txt.value
}

const secmail = async (params: Record<string, string>): Promise<any> => {
  params.domain = domain
  const query = Object.keys(params)
    .map(k => {
      return `${encodeURIComponent(k)}=${encodeURIComponent(params[k])}`
    })
    .join('&')
  const url = `https://www.1secmail.com/api/v1/?${query}`
  const res = await fetch(url)
  return res.json()
}

const getSigninLink = async (login: string): Promise<string> => {
  const list = (await secmail({
    action: 'getMessages',
    login,
  })) as any[]
  if (list.length === 0) {
    await sleep(250)
    return await getSigninLink(login)
  }
  const message = await secmail({
    action: 'readMessage',
    login,
    id: list[0].id,
  })
  const link = /'http.*oobCode.*'/.exec(message.htmlBody)?.[0]
  if (!link) {
    throw new Error('link not found in email')
  }
  // decode and trim leading and trailing single quote
  return decodeHTML(link).slice(1, -1)
}

// @ts-ignore skip is real
QUnit.test.skip('email link signin', async assert => {
  // random new email address
  const login = nanoid()
  const email = `${login}@${domain}`

  const states = [
    (u?: User) => assert.equal(u, undefined, 'start off without a user'),
    (u?: User) => assert.equal(u?.email, email, 'sign in'),
    (u?: User) => assert.equal(u, undefined, 'account deleted'),
  ]

  const done = assert.async(states.length)
  const auth = await Auth.new({
    apiKey,
    name: nanoid(),
  })

  // monitor the various auth state changes
  let count = 0
  auth.subscribe(user => {
    const f = states[count]
    if (!f) {
      assert.ok(false, 'unexpected assertion')
    }
    count++
    f(user)
    done()
  })

  // complete the email sign in flow
  await auth.sendEmailSigninLink(email)
  const emailLink = await getSigninLink(login)
  await auth.handleEmailSigninRedirect(emailLink)

  // force a refresh by mucking with the data
  /* eslint-disable @typescript-eslint/no-non-null-assertion */
  auth.user!.expiresAt = Date.now() - 10000
  /* eslint-disable @typescript-eslint/no-non-null-assertion */
  const oldExpiresAt = auth.user!.expiresAt
  // trigger a refresh
  await auth.getBearerToken()
  assert.notEqual(auth.user?.expiresAt, oldExpiresAt, 'expires changes')

  // delete the user
  await auth.delete()
})

QUnit.test('email sign-up / sign-in', async assert => {
  // random new email address
  const login = nanoid()
  const password = nanoid()
  const email = `${login}@${domain}`

  const states = [
    (u?: User) => assert.equal(u, undefined, 'start off without a user'),
    (u?: User) => assert.equal(u?.email, email, 'sign up'),
    (u?: User) => assert.equal(u, undefined, 'sign out'),
    (u?: User) => assert.equal(u?.email, email, 'sign in'),
    (u?: User) => assert.equal(u, undefined, 'account deleted'),
  ]

  const done = assert.async(states.length)
  const auth = await Auth.new({
    apiKey,
    name: nanoid(),
  })

  // monitor the various auth state changes
  let count = 0
  auth.subscribe(user => {
    const f = states[count]
    if (!f) {
      assert.ok(false, 'unexpected assertion')
    }
    count++
    f(user)
    done()
  })

  // complete the email/password flow
  await auth.signUp({
    email,
    password,
  })
  await auth.signOut()
  await auth.signIn({
    email,
    password,
  })
  await auth.delete()
})

QUnit.test('subscribe with immediate = false', async assert => {
  // random new email address
  const login = nanoid()
  const password = nanoid()
  const email = `${login}@${domain}`

  const states = [
    (u?: User) => assert.equal(u?.email, email, 'sign up'),
    (u?: User) => assert.equal(u, undefined, 'account deleted'),
  ]

  const done = assert.async(states.length)
  const auth = await Auth.new({
    apiKey,
    name: nanoid(),
  })

  // monitor the various auth state changes
  let count = 0
  auth.subscribe(user => {
    const f = states[count]
    if (!f) {
      assert.ok(false, 'unexpected assertion')
    }
    count++
    f(user)
    done()
  }, false)

  await auth.signUp({
    email,
    password,
  })
  await auth.delete()
})
