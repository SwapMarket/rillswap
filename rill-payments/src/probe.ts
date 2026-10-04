import { probeExternalProviders } from "./discovery";
if (import.meta.main) console.log(JSON.stringify(await probeExternalProviders(), null, 2));
