from datetime import datetime
from typing import List, Dict, Any


class Account:
    """
    Базовый банковский счёт.

    - holder: владелец счёта
    - _balance: текущий баланс
    - operations_history: список операций
    """

    def __init__(self, account_holder: str, balance: float = 0.0) -> None:
        if balance < 0:
            raise ValueError("Начальный баланс не может быть отрицательным")

        self.holder: str = account_holder
        self._balance: float = float(balance)
        self.operations_history: List[Dict[str, Any]] = []

    @property
    def balance(self) -> float:
        """Геттер для баланса"""
        return self._balance

    def _add_operation(
            self,
            *,
            op_type: str,
            amount: float,
            status: str,
            balance_after: float,
            extra: Dict[str, Any] | None = None,
    ) -> None:
        """
        Внутренний метод для записи операции в историю.
        """
        record = {
            "type": op_type,    # 'deposit' или 'withdraw'
            "amount": amount,
            "datetime": datetime.now(), # объект datetime для дальнейшей аналитики
            "balance_after": balance_after,
            "status": status,    # 'success' или 'fail'
        }
        if extra:
            record.update(extra)

        self.operations_history.append(record)

    def deposit(self, amount: float) -> None:
        """
        Пополнение счёта.

        - Сумма должна быть > 0.
        """
        if amount <= 0:
            self._add_operation(
                op_type="deposit",
                amount=amount,
                status="fail",
                balance_after=self._balance,
                extra={"reason": "Amount must be positive"},
            )
            return

        self._balance += amount

        self._add_operation(
            op_type="deposit",
            amount=amount,
            status="success",
            balance_after=self._balance,
        )

    def withdraw(self, amount: float) -> None:
        """
        Снятие средств.

        - Сумма должна быть > 0.
        - Нельзя уйти в минус.
        """
        if amount <= 0:
            self._add_operation(
                op_type="withdraw",
                amount=amount,
                status="fail",
                balance_after=self._balance,
                extra={"reason": "Amount must be positive"},
            )
            return

        if amount > self._balance:
            self._add_operation(
                op_type="withdraw",
                amount=amount,
                status="fail",
                balance_after=self._balance,
                extra={"reason": "Insufficient funds"},
            )
            return

        self._balance -= amount

        self._add_operation(
            op_type="withdraw",
            amount=amount,
            status="success",
            balance_after=self._balance,
        )

    def get_balance(self) -> float:
        """Возвращает текущий баланс."""
        return self._balance

    def get_history(self) -> List[Dict[str, Any]]:
        """
        Возвращает историю операций в виде списка словарей.
        Копируем записи, чтобы их нельзя было сломать снаружи.
        """
        return [record.copy() for record in self.operations_history]


class CreditAccount(Account):
    """
    Кредитный счёт.

    Особенности:
    - Можно уходить в минус до -credit_limit.
    - Показывает доступный кредит.
    - В историю операций добавляется флаг использования кредитных средств.
    """

    def __init__(
            self,
            account_holder: str,
            balance: float = 0.0,
            credit_limit: float = 0.0,
    ) -> None:
        if credit_limit < 0:
            raise ValueError("Кредитный лимит не может быть отрицательным")

        self._credit_limit: float = float(credit_limit)

        if balance < -self._credit_limit:
            raise ValueError(
                "Начальный баланс ниже допустимого кредитного лимита"
            )

        super().__init__(account_holder, balance)

    def get_available_credit(self) -> float:
        """
        Сколько кредитных средств ещё доступно.
        Формула: текущий баланс + кредитный лимит.
        """
        return self._credit_limit + self._balance

    def withdraw(self, amount: float) -> None:
        """
        Снятие с учётом кредитного лимита.
        """
        if amount <= 0:
            self._add_operation(
                op_type="withdraw",
                amount=amount,
                status="fail",
                balance_after=self._balance,
                extra={"reason": "Amount must be positive"},
            )
            return

        new_balance = self._balance - amount

        if new_balance < -self._credit_limit:
            self._add_operation(
                op_type="withdraw",
                amount=amount,
                status="fail",
                balance_after=self._balance,
                extra={"reason": "Credit limit exceeded"},
            )
            return

        used_credit = new_balance < 0

        self._balance = new_balance

        self._add_operation(
            op_type="withdraw",
            amount=amount,
            status="success",
            balance_after=self._balance,
            extra={
                "used_credit": used_credit,
                "available_credit_after": self.get_available_credit(),
            },
        )

    def deposit(self, amount: float) -> None:
        """
        Пополнение кредитного счёта.

        Если баланс был отрицательный, пополнение сначала гасит кредит.
        В истории фиксируется, были ли задействованы кредитные средства.
        """
        if amount <= 0:
            self._add_operation(
                op_type="deposit",
                amount=amount,
                status="fail",
                balance_after=self._balance,
                extra={"reason": "Amount must be positive"},
            )
            return

        before = self._balance
        self._balance += amount
        used_credit = before < 0

        self._add_operation(
            op_type="deposit",
            amount=amount,
            status="success",
            balance_after=self._balance,
            extra={
                "used_credit": used_credit,
                "available_credit_after": self.get_available_credit(),
            },
        )
