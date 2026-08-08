/*
 * Benign C-source fixture for AIDebug's --source workflow.
 * It performs a small arithmetic transformation and has no external effects.
 */

static __attribute__((noinline)) int add_one(int value)
{
    return value + 1;
}

int main(void)
{
    return add_one(4);
}
