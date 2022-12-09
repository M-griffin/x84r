# -*- coding: utf-8 -*-
""" Session Manager for x/84. """


class SessionManager:
    """ Session Manager Singleton Class. """

    class SessionSubManager:
        """ Core Singleton Object for Global State Management """
        __session_list = []

        def __init__(self):
            self.val = None

        def __str__(self):
            return 'self' + self.val

        def add_session(self, session):
            """ Add a Session to the Managed List """
            self.__session_list.append(session)

    instance = None

    # __new__ always a class method
    def __new__(cls):
        if not SessionManager.instance:
            SessionManager.instance = SessionManager.SessionSubManager()
        return SessionManager.instance

    def __getattr__(self, name):
        return getattr(self.instance, name)

    def __setattr__(self, name, value) -> None:
        return setattr(self.instance, name, value)
