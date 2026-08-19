import StaticdeployClient from "@staticdeploy/sdk";
import ConfigProvider from "antd/lib/config-provider";
import enUS from "antd/locale/en_US";
import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime";
import compact from "lodash/compact";
import { createRoot } from "react-dom/client";
import { Provider } from "react-redux";
import { BrowserRouter } from "react-router-dom";

import AuthService from "./common/AuthService";
import JwtAuthStrategy from "./common/AuthService/JwtAuthStrategy";
import OidcAuthStrategy from "./common/AuthService/OidcAuthStrategy";
import ServerSessionAuthStrategy from "./common/AuthService/ServerSessionAuthStrategy";
import StaticdeployClientContext from "./common/StaticdeployClientContext";
import InitSpinner from "./components/InitSpinner";
import config from "./config";
import "./index.css";
import reduxStore from "./reduxStore";
import Root from "./Root";

dayjs.extend(relativeTime);

async function start() {
    const staticdeployClient = new StaticdeployClient({
        apiUrl: config.apiUrl,
    });

    const authService = new AuthService(
        config.authEnforced,
        compact([
            config.jwtEnabled ? new JwtAuthStrategy() : null,
            config.serverSessionEnabled
                ? new ServerSessionAuthStrategy(
                      config.serverSessionAuthUrl,
                      config.serverSessionProviderName
                  )
                : null,
            config.oidcEnabled
                ? new OidcAuthStrategy(
                      config.oidcConfigurationUrl,
                      config.oidcClientId,
                      config.oidcRedirectUrl,
                      config.oidcProviderName
                  )
                : null,
        ]),
        staticdeployClient
    );

    const rootElement = document.getElementById("root");
    if (!rootElement)
        throw new Error("Missing management console root element");
    const root = createRoot(rootElement);

    // Render a spinner while the authService is initializing
    root.render(<InitSpinner />);

    await authService.init();

    if (OidcAuthStrategy.isSilentRedirectPage()) {
        // In the silent redirect iframe we only care about initializing the
        // authService, which will take care of concluding the silent redirect
        // process
        return;
    }

    // Render the app once the authService is initialized
    root.render(
        <StaticdeployClientContext.Provider value={staticdeployClient}>
            <ConfigProvider locale={enUS}>
                <BrowserRouter>
                    <Provider store={reduxStore}>
                        <Root authService={authService} />
                    </Provider>
                </BrowserRouter>
            </ConfigProvider>
        </StaticdeployClientContext.Provider>
    );
}
start();
