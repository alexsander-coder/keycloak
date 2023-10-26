import { useContext, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom"
import { AuthContext } from "./AuthProvider";

export function Callback() {

  const { hash } = useLocation();
  const { login, auth } = useContext(AuthContext)
  const navigate = useNavigate()

  // console.log(hash, 'details hash')

  useEffect(() => {

    if (auth) {
      navigate("/login")
      return;
    }

    const searchParams = new URLSearchParams(hash.replace("#", ""));
    const accessToken = searchParams.get("access_token") as string;
    const idToken = searchParams.get("id_token") as string;
    const state = searchParams.get("state") as string;
    const code = searchParams.get("code") as string;


    if (!accessToken || !idToken || !state) {
      //uma opção viavel é navegar para o login novamente
      // return;
      navigate("/login");
    }

    login(accessToken, idToken, code, state);

    console.log('funfou caraio')
    //podendo fazer um redirectprefer ~>  login
  }, [hash, login, auth, navigate]);

  return <div>Loading Callback...</div>
}
