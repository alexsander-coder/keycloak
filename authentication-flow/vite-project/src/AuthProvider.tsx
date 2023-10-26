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
    state: string
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
  const makeLogin = useCallback((accessToken: string, idToken: string, state: string) => {
    const authData = utils.login(accessToken, idToken, state);
    setData((oldData) => ({
      auth: authData,
      makeLoginUrl: oldData.makeLoginUrl,
      makeLogoutUrl: oldData.makeLogoutUrl,
      login: oldData.login,
    }));
    return authData;
  }, []);

  const [data, setData] = useState({
    auth: utils.getAuth(),
    makeLoginUrl: utils.makeLoginUrl,
    makeLogoutUrl: utils.makeLogoutUrl,
    login: makeLogin,
    //se der erro colocar a function aqui logout: () => {} com o @ts-expert
  });

  return (
    <AuthContext.Provider value={data}>{props.children}</AuthContext.Provider>
  );
};