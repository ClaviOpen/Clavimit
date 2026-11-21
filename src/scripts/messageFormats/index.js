import { V1Format } from "./V1Format.js";
import { MESSAGE_BEGIN, MESSAGE_END } from "../config.js";
import { ClavimitError } from "../exeptions.js";

const SUPPORTED_FORMATS = [new V1Format()];
const FORMATS = new Map(SUPPORTED_FORMATS.map((f) => [f.version, f]));
export const DEFAULT_FORMAT = FORMATS.get(1);

export function getFormat(version) {
    return FORMATS.get(version);
}

export function availableFormats() {
    return SUPPORTED_FORMATS;
}

function getJsonFromText(text) {
    if (!text) {
        throw new ClavimitError(
            "INVALID_MESSAGE",
            "No Clavimit message was found",
        );
    }
    const start = text.indexOf(MESSAGE_BEGIN);
    const finish = text.indexOf(MESSAGE_END);

    if (start === -1 || finish === -1) {
        throw new ClavimitError("INVALID_MESSAGE", "Not a Clavimit message");
    }

    return text.slice(start + MESSAGE_BEGIN.length, finish).trim();
}

export function deserializeMessage(json) {
    let obj;
    try {
        obj = JSON.parse(json);
    } catch {
        throw new ClavimitError(
            "INVALID_MESSAGE",
            "The Clavimit message contains invalid JSON.",
        );
    }

    const format = getFormat(obj?.version);
    if (!format) {
        throw new ClavimitError(
            "UNSUPPORTED_VERSION",
            "This message was created with a newer version of Clavimit. Please update.",
        );
    }
    if (!format.validateMessage(obj)) {
        throw new ClavimitError(
            "INVALID_MESSAGE",
            "The Clavimit message does not satisfy the expected format.",
        );
    }

    return { format, message: obj };
}

export function parseMessage(text) {
    if (!text) {
        throw new ClavimitError(
            "INVALID_MESSAGE",
            "No Clavimit message was found",
        );
    }
    const start = text.indexOf(MESSAGE_BEGIN);
    const finish = text.indexOf(MESSAGE_END);

    if (start === -1 || finish === -1) {
        throw new ClavimitError("INVALID_MESSAGE", "Not a Clavimit message");
    }

    const json = text.slice(start + MESSAGE_BEGIN.length, finish).trim();

    return deserializeMessage(json);
}
