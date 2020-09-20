// Storage to persist authentication information.
export interface AuthStorage {
  set(key: string, value: string): Promise<void>;
  get(key: string): Promise<string | undefined>;
  remove(key: string): Promise<void>;
}

// The minimal User maintained for Authentication and Authorization purposes.
export interface User {
  localId: string;
  email: string;
  refreshToken: string;
  idToken: string;
  expiresAt: number;
}

// There are other fields that may be included as documented at:
// https://cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/signUp
// An empty object will create an anonymous user if the project allows for it.
export interface SignUpRequest {
  email?: string;
  password?: string;
  displayName?: string;
  photoUrl?: string;
}

// There are other fields that may be included as documented at:
// https://cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/signInWithPassword
export interface SignInRequest {
  email: string;
  password: string;
}

// There are other fields that may be included as documented at:
// https://cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/resetPassword
export interface ResetPasswordRequest {
  oobCode?: string;
  email?: string;
  oldPassword?: string;
  newPassword: string;
}

// Authentication & Authorization.
export class Auth {
  private readonly kUser: string;
  private readonly kEmail: string;
  private _user?: User;
  private _refresh?: Promise<void>;
  private _subscribers: { (user: User | undefined): void }[] = [];

  private constructor(
    private readonly apiKey: string,
    private readonly storage: AuthStorage,
    name: string,
  ) {
    this.kUser = `auth:user:${name}:${this.apiKey}`;
    this.kEmail = `auth:email:${name}:${this.apiKey}`;
  }

  // Construct a new Auth instance.
  public static async new({
    apiKey,
    storage,
    name = '',
  }: {
    apiKey: string;
    storage: AuthStorage;
    name?: string;
  }): Promise<Auth> {
    const auth = new Auth(apiKey, storage, name);
    const j = await auth.storage.get(auth.kUser);
    if (j) {
      await auth.setUser(JSON.parse(j), false);
    }
    return auth;
  }

  // Get the current User if available.
  public get user(): User | undefined {
    return this._user;
  }

  private async setUser(user?: User, save = true) {
    this._user = user;
    this._subscribers.forEach((cb) => cb(this._user));
    if (save) {
      if (user) {
        await this.storage.set(this.kUser, JSON.stringify(this._user));
      } else {
        await this.storage.remove(this.kUser);
      }
    }
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private async handleResponse(d: any): Promise<void> {
    const old = this._user;
    const expiresAt =
      Date.now() + parseInt(d.expiresIn ?? d.expires_in ?? 3600) * 1000;
    const user: User = {
      localId: d.localId ?? old?.localId,
      email: d.email ?? old?.email,
      refreshToken: d.refreshToken ?? d.refresh_token ?? old?.refreshToken,
      idToken: d.idToken ?? d.id_token ?? old?.idToken,
      expiresAt,
    };
    await this.setUser(user);
  }

  // Sign out the User and clear stored Auth data.
  public async signOut(): Promise<void> {
    await this.setUser();
  }

  // Sign-Up a new user.
  // https://cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/signUp
  public async signUp(req: SignUpRequest): Promise<void> {
    const data = await this.api('signUp', req);
    await this.handleResponse(data);
  }

  // Sign-In exsiting user.
  // https://cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/signInWithPassword
  public async signIn(req: SignInRequest): Promise<void> {
    const data = await this.api('signInWithPassword', req);
    await this.handleResponse(data);
  }

  // Reset password for user.
  // https://cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/resetPassword
  public async resetPassword(req: ResetPasswordRequest): Promise<void> {
    await this.api('resetPassword', req);
  }

  // Delete the user. The removes the account entirely.
  // https://cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/delete
  public async delete(): Promise<void> {
    await this.api('delete', { idToken: this.user?.idToken });
    await this.signOut();
  }

  // Get the bearer token, if one is available. Refresh it if necessary. This
  // method can be used as a TokenSource in @daaku/firebase-rest-api.
  public async getBearerToken(): Promise<string | undefined> {
    if (!this._user?.refreshToken) {
      return;
    }
    await this.refresh();
    return this._user?.idToken;
  }

  // Subscribe to get notified of user changes. Callback is invoked once
  // immediately with current user. Returned function can be used to
  // unsubscribe.
  public subscribe(cb: (user: User | undefined) => void): () => void {
    this._subscribers.push(cb);
    cb(this._user);
    return () => {
      this._subscribers = this._subscribers.filter((e) => e !== cb);
    };
  }

  // Send a link to the provided email address that allows signing in.
  public async sendEmailSigninLink(email: string): Promise<void> {
    await this.storage.set(this.kEmail, email);
    await this.api('sendOobCode', {
      requestType: 'EMAIL_SIGNIN',
      email,
    });
  }

  // This should be invoked on the page where the user lands from an email sign
  // in link.
  public async handleEmailSigninRedirect(url = location.href): Promise<void> {
    const oobCode = url.match(/[?&]oobCode=([^&]+)/)?.[1];
    if (!oobCode) {
      throw new Error('oobCode not found in URL');
    }
    const email = await this.storage.get(this.kEmail);
    if (!email) {
      throw new Error('email not found in storage');
    }
    const data = await this.api('signInWithEmailLink', {
      oobCode,
      email,
    });
    await this.handleResponse(data);
    await this.storage.remove(this.kEmail);
  }

  // This allows calling for the various APIs documented here:
  // https://cloud.google.com/identity-platform/docs/reference/rest/v1/accounts
  // eslint-disable-next-line
  public async api(endpoint: string, body: any): Promise<any> {
    const url =
      endpoint === 'token'
        ? `https://securetoken.googleapis.com/v1/token?key=${this.apiKey}`
        : `https://identitytoolkit.googleapis.com/v1/accounts:${endpoint}?key=${this.apiKey}`;
    const response = await fetch(url, {
      method: 'post',
      body: JSON.stringify(body),
    });
    const data = await response.json();
    if (!response.ok) {
      throw Error(data);
    }
    return data;
  }

  private async refresh(): Promise<void> {
    if (!this._user) {
      throw new Error('refresh called without existing user');
    }
    const refreshToken = this._user.refreshToken;
    if (Date.now() < this._user.expiresAt) {
      return;
    }
    if (!this._refresh) {
      this._refresh = (async () => {
        const data = await this.api('token', {
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
        });
        await this.handleResponse(data);
      })();
    }
    await this._refresh;
    delete this._refresh;
  }
}
