import { File } from '@asyncapi/generator-react-sdk';

// Import all template components
import CargoToml from './Cargo.toml';
import ReadmeMd from './README.md';
import LibRs from './src/lib.rs';
import ErrorRs from './src/error.rs';
import ConfigRs from './src/config.rs';
import ModelsRs from './src/models.rs';
import ClientRs from './src/client.rs';
import MainRs from './src/main.rs';
import GitIgnore from './.gitignore';
import ConfigExample from './config.toml.example';

export default function ({ asyncapi, params }) {
    return [
        <CargoToml asyncapi={asyncapi} params={params} />,
        <ReadmeMd asyncapi={asyncapi} params={params} />,
        <LibRs asyncapi={asyncapi} params={params} />,
        <ErrorRs asyncapi={asyncapi} params={params} />,
        <ConfigRs asyncapi={asyncapi} params={params} />,
        <ModelsRs asyncapi={asyncapi} params={params} />,
        <ClientRs asyncapi={asyncapi} params={params} />,
        <MainRs asyncapi={asyncapi} params={params} />,
        <GitIgnore />,
        <ConfigExample asyncapi={asyncapi} params={params} />
    ];
}
