import abc


class LanguageModel(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def __init__(self, model: str) -> None:
        """Providers are built from the name of the model they will serve.

        Declared because instantiate_model() calls the class with exactly
        that, and every provider already implements it.
        """

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