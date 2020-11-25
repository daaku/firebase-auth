/* eslint-disable @typescript-eslint/no-explicit-any */
import { customAlphabet } from 'nanoid/index.js';

import { Auth, User } from '../src';

const apiKey = 'AIzaSyCnFgFqO3d7RbJDcNAp_eO21KSOISCP9IU';
const nanoid = customAlphabet('abcdefghijklmnopqrstuvwxyz', 16);
const domain = '1secmail.com';

async function sleep(delayMS: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, delayMS);
  });
}

function decodeHTML(html: string): string {
  const txt = document.createElement('textarea');
  txt.innerHTML = html;
  return txt.value;
}

async function secmail(params: { [key: string]: string }): Promise<any> {
  params.domain = domain;
  const query = Object.keys(params)
    .map((k) => {
      return `${encodeURIComponent(k)}=${encodeURIComponent(params[k])}`;
    })
    .join('&');
  const url = `https://www.1secmail.com/api/v1/?${query}`;
  const res = await fetch(url);
  return res.json();
}

async function getSigninLink(login: string): Promise<string> {
  const list = (await secmail({
    action: 'getMessages',
    login,
  })) as any[];
  if (list.length === 0) {
    await sleep(250);
    return await getSigninLink(login);
  }
  const message = await secmail({
    action: 'readMessage',
    login,
    id: list[0].id,
  });
  const link = /'http.*oobCode.*'/.exec(message.htmlBody)?.[0];
  if (!link) {
    throw new Error('link not found in email');
  }
  // decode and trim leading and trailing single quote
  return decodeHTML(link).slice(1, -1);
}

QUnit.test('email link signin', async (assert) => {
  // random new email address
  const login = nanoid();
  const email = `${login}@${domain}`;

  const states = [
    (u?: User) => assert.equal(u, undefined, 'start off without a user'),
    (u?: User) => assert.equal(u?.email, email, 'sign in'),
    (u?: User) => assert.equal(u, undefined, 'account deleted'),
  ];

  const done = assert.async(states.length);
  const auth = await Auth.new({
    apiKey,
    name: nanoid(),
  });

  // monitor the various auth state changes
  let count = 0;
  auth.subscribe(async (user) => {
    const f = states[count];
    if (!f) {
      assert.ok(false, 'unexpected assertion');
    }
    count++;
    f(user);
    done();
  });

  // complete the email sign in flow
  await auth.sendEmailSigninLink(email);
  const emailLink = await getSigninLink(login);
  await auth.handleEmailSigninRedirect(emailLink);

  // force a refresh by mucking with the data
  // @ts-expect-error accessing private members
  auth._user.expiresAt = Date.now() - 10000;
  const oldExpiresAt = auth.user!.expiresAt;
  // @ts-expect-error accessing private members
  await auth.refresh();
  assert.notEqual(auth.user?.expiresAt, oldExpiresAt, 'expires changes');

  // delete the user
  await auth.delete();
});

QUnit.test('email sign-up / sign-in', async (assert) => {
  // random new email address
  const login = nanoid();
  const password = nanoid();
  const email = `${login}@${domain}`;

  const states = [
    (u?: User) => assert.equal(u, undefined, 'start off without a user'),
    (u?: User) => assert.equal(u?.email, email, 'sign up'),
    (u?: User) => assert.equal(u, undefined, 'sign out'),
    (u?: User) => assert.equal(u?.email, email, 'sign in'),
    (u?: User) => assert.equal(u, undefined, 'account deleted'),
  ];

  const done = assert.async(states.length);
  const auth = await Auth.new({
    apiKey,
    name: nanoid(),
  });

  // monitor the various auth state changes
  let count = 0;
  auth.subscribe(async (user) => {
    const f = states[count];
    if (!f) {
      assert.ok(false, 'unexpected assertion');
    }
    count++;
    f(user);
    done();
  });

  // complete the email/password flow
  await auth.signUp({
    email,
    password,
  });
  await auth.signOut();
  await auth.signIn({
    email,
    password,
  });
  await auth.delete();
});
