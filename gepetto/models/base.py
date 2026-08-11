import abc
import json


class LanguageModel(metaclass=abc.ABCMeta):
    """Base class for providers.

    Settings are expressed in the configuration in conceptual terms
    (REASONING_EFFORT, TEMPERATURE) and each provider translates them into
    whatever its API actually calls them. The same idea has at least four
    spellings across the providers here -- reasoning_effort, reasoning.effort,
    output_config.effort, thinking.type -- so translation has to belong to the
    provider rather than the caller.

    EXTRA_OPTIONS is the escape hatch: raw JSON merged into the request last,
    for parameters that are not modelled, including ones that did not exist
    when this was written.
    """

    # Configuration section this provider reads its own settings from.
    CONFIG_SECTION = None

    def config_value(self, option, default=None):
        """Read one option from this provider's configuration section."""
        # Imported lazily: gepetto.config imports model_manager, which imports
        # this module, so a module-level import would be a cycle.
        import gepetto.config

        if not self.CONFIG_SECTION:
            return default
        value = gepetto.config.get_config(self.CONFIG_SECTION, option)
        value = (value or "").strip()
        return value or default

    # -- translation hooks; override in providers that spell things differently

    def apply_reasoning_effort(self, options, effort):
        """Chat-completions spelling. Providers with another one override this.

        "none" means the user asked for reasoning off. Chat completions has no
        value for that, so the parameter is omitted; providers that can express
        it explicitly, as DeepSeek's Responses API does, override this.
        """
        if effort == "none":
            return
        options["reasoning_effort"] = effort

    def supports_temperature(self) -> bool:
        """Whether the selected model accepts a sampling temperature.

        Support is per model, not per provider: OpenAI's reasoning models
        reject the parameter with a 400 rather than ignoring it, so one
        setting on a provider section would break every request the moment
        such a model is selected.
        """
        return True

    def apply_temperature(self, options, temperature):
        if not self.supports_temperature():
            print(
                f"Gepetto: {self.model} does not accept a temperature; ignoring "
                f"TEMPERATURE. Set it through EXTRA_OPTIONS to send it anyway."
            )
            return
        options["temperature"] = temperature

    # -- resolution

    def _configured_effort(self, options):
        """Effort from the caller or the config, or None to send nothing.

        None means "say nothing and let the provider do whatever it does by
        default", which is not the same as off: DeepSeek, for one, enables
        thinking by default.
        """
        effort = options.pop("reasoning_effort", None) or self.config_value("REASONING_EFFORT")
        effort = str(effort or "").strip().lower()
        if not effort:
            return None
        # "off" is a request, not an absence: for a provider that reasons by
        # default it has to be transmitted, so it is normalised rather than
        # dropped here and each provider decides how to express it.
        if effort in ("off", "0", "false", "disabled"):
            return "none"
        return effort

    def _configured_temperature(self):
        raw = self.config_value("TEMPERATURE")
        if raw is None:
            return None
        try:
            return float(raw)
        except ValueError:
            print(f"Gepetto: [{self.CONFIG_SECTION}] TEMPERATURE={raw!r} is not a number; ignoring.")
            return None

    def _extra_options(self):
        raw = self.config_value("EXTRA_OPTIONS")
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except ValueError as e:
            print(f"Gepetto: [{self.CONFIG_SECTION}] EXTRA_OPTIONS is not valid JSON ({e}); ignoring.")
            return {}
        if not isinstance(parsed, dict):
            print(f"Gepetto: [{self.CONFIG_SECTION}] EXTRA_OPTIONS must be a JSON object; ignoring.")
            return {}
        return parsed

    def apply_settings(self, options):
        """Return options with this provider's configured settings applied."""
        options = dict(options or {})

        effort = self._configured_effort(options)
        if effort:
            self.apply_reasoning_effort(options, effort)

        temperature = self._configured_temperature()
        if temperature is not None:
            self.apply_temperature(options, temperature)

        # Last, so it can override anything above deliberately.
        options.update(self._extra_options())
        return options
    @abc.abstractmethod
    def query_model_async(self, query, cb, stream, additional_model_options) -> None:
        pass

    def __eq__(self, other):
        return self.get_menu_name() == other.get_menu_name()

    def __hash__(self):
        return self.get_menu_name().__hash__()

    @staticmethod
    @abc.abstractmethod
    def supported_models() -> list[str]:
        pass

    @staticmethod
    @abc.abstractmethod
    def get_menu_name() -> str:
        pass

    @staticmethod
    @abc.abstractmethod
    def is_configured_properly() -> bool:
        pass