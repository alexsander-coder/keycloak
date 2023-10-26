import { PropsWithChildren, createContext, useCallback, useState } from 'react';
import * as utils from './utils';
import { JWTPayload } from 'jose';

type AuthContextProps = {
  auth: JWTPayload | null;
  makeLoginUrl: () => string;
  makeLogoutUrl: () => any;
  login: (
    accessToken: string,
    idToken: string,
    code: string,
    state: string,
  ) => JWTPayload;
};


const initContextData: AuthContextProps = {
  auth: null,
  makeLoginUrl: utils.makeLoginUrl,
  //// @ts-expect-error - this is a mock function
  makeLogoutUrl: () => { },
  //@ts-expect-error - this is a mock function
  login: () => { },
};


export const AuthContext = createContext(initContextData);

export const AuthProvider = (props: PropsWithChildren) => {
  const makeLogin = useCallback((accessToken: string, idToken: string, code: string, state: string) => {
    // @ts-expect-error - for refresh token parameter
    const authData = utils.login(accessToken, idToken, null, state);
    setData((oldData) => ({
      auth: authData,
      makeLoginUrl: oldData.makeLoginUrl,
      makeLogoutUrl: oldData.makeLogoutUrl,
      login: oldData.login,
    }));

    utils.exchangeCodeForToken(code).then(authData => {
      setData((oldData) => ({
        auth: authData,
        makeLoginUrl: oldData.makeLoginUrl,
        makeLogoutUrl: oldData.makeLogoutUrl,
        login: oldData.login,
      }));
    });

    return authData;

  }, []);

  const [data, setData] = useState({
    auth: utils.getAuth(),
    makeLoginUrl: utils.makeLoginUrl,
    makeLogoutUrl: utils.makeLogoutUrl,
    login: makeLogin,
  });

  return (
    <AuthContext.Provider value={data}>{props.children}</AuthContext.Provider>
  );
};