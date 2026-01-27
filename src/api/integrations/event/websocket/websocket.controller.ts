import { PrismaRepository } from '@api/repository/repository.service';
import { WAMonitoringService } from '@api/services/monitor.service';
import { Auth, configService, Cors, Log, Websocket } from '@config/env.config';
import { Logger } from '@config/logger.config';
import { Server } from 'http';
import { Server as SocketIO, Socket } from 'socket.io';

import { EmitData, EventController, EventControllerInterface } from '../event.controller';

export class WebsocketController extends EventController implements EventControllerInterface {
  private io: SocketIO;
  private corsConfig: Array<any>;
  private readonly logger = new Logger('WebsocketController');

  constructor(prismaRepository: PrismaRepository, waMonitor: WAMonitoringService) {
    super(prismaRepository, waMonitor, configService.get<Websocket>('WEBSOCKET')?.ENABLED, 'websocket');

    this.cors = configService.get<Cors>('CORS').ORIGIN;
  }

  public init(httpServer: Server): void {
    if (!this.status) {
      return;
    }

    this.socket = new SocketIO(httpServer, {
      cors: { origin: this.cors },
      allowRequest: async (req, callback) => {
        try {
          const { remoteAddress } = req.socket;
          const websocketConfig = configService.get<Websocket>('WEBSOCKET');
          const allowedHosts = (websocketConfig.ALLOWED_HOSTS || '127.0.0.1,::1,::ffff:127.0.0.1')
            .split(',')
            .map((host) => host.trim())
            .filter(Boolean);
          const allowAllHosts = allowedHosts.includes('*');
          const normalizeAddress = (address: string | undefined) =>
            address?.replace(/^::ffff:/, '') || '';
          const strippedAddress = normalizeAddress(remoteAddress);

          const isAllowedHost =
            allowAllHosts ||
            allowedHosts.some(
              (host) => host === remoteAddress || host === strippedAddress || host === 'localhost',
            );

          if (isAllowedHost) {
            return callback(null, true);
          }

          return callback('Host not allowed', false);
        } catch (error) {
          this.logger.error('Authentication error:');
          this.logger.error(error);
          callback('Authentication error', false);
        }
      },
    });

    const registerHandlers = (socket: Socket) => {
      this.logger.info('User connected');

      socket.on('disconnect', () => {
        this.logger.info('User disconnected');
      });

      socket.on('sendNode', async (data) => {
        try {
          await this.waMonitor.waInstances[data.instanceId].baileysSendNode(data.stanza);
          this.logger.info('Node sent successfully');
        } catch (error) {
          this.logger.error('Error sending node:');
          this.logger.error(error);
        }
      });
    };

    this.socket.use(this.createAuthMiddleware());
    this.socket.on('connection', registerHandlers);

    this.socket.of(/^\/.+/).use(this.createAuthMiddleware()).on('connection', registerHandlers);

    this.logger.info('Socket.io initialized');
  }

  private set cors(cors: Array<any>) {
    this.corsConfig = cors;
  }

  private get cors(): string | Array<any> {
    return this.corsConfig?.includes('*') ? '*' : this.corsConfig;
  }

  private set socket(socket: SocketIO) {
    this.io = socket;
  }

  public get socket(): SocketIO {
    return this.io;
  }

  private createAuthMiddleware() {
    return async (socket: Socket, next: (err?: Error) => void) => {
      try {
        const authKey = socket.handshake.auth?.apikey as string | undefined;
        const protocolHeader = socket.handshake.headers['sec-websocket-protocol'] as string | undefined;
        let apiKey = authKey;

        if (!apiKey && protocolHeader) {
          const protocols = protocolHeader.split(',').map((value) => value.trim());
          const apikeyIndex = protocols.indexOf('apikey');
          if (apikeyIndex !== -1 && protocols[apikeyIndex + 1]) {
            apiKey = protocols[apikeyIndex + 1];
          }
        }

        if (!apiKey) {
          this.logger.error('Connection rejected: apiKey not provided');
          return next(new Error('apiKey is required'));
        }

        const instance = await this.prismaRepository.instance.findFirst({ where: { token: apiKey } });

        if (!instance) {
          const globalToken = configService.get<Auth>('AUTHENTICATION').API_KEY.KEY;
          if (apiKey !== globalToken) {
            this.logger.error('Connection rejected: invalid global token');
            return next(new Error('Invalid global token'));
          }
        }

        return next();
      } catch (error) {
        this.logger.error('Authentication error:');
        this.logger.error(error);
        return next(new Error('Authentication error'));
      }
    };
  }

  public async emit({
    instanceName,
    origin,
    event,
    data,
    serverUrl,
    dateTime,
    sender,
    apiKey,
    integration,
    extra,
  }: EmitData): Promise<void> {
    if (integration && !integration.includes('websocket')) {
      return;
    }

    if (!this.status) {
      return;
    }

    const configEv = event.replace(/[.-]/gm, '_').toUpperCase();
    const logEnabled = configService.get<Log>('LOG').LEVEL.includes('WEBSOCKET');
    const message = {
      ...(extra ?? {}),
      event,
      instance: instanceName,
      data,
      server_url: serverUrl,
      date_time: dateTime,
      sender,
      apikey: apiKey,
    };

    if (configService.get<Websocket>('WEBSOCKET')?.GLOBAL_EVENTS) {
      this.socket.emit(event, message);

      if (logEnabled) {
        this.logger.log({ local: `${origin}.sendData-WebsocketGlobal`, ...message });
      }
    }

    try {
      const instance = await this.get(instanceName);

      if (!instance?.enabled) {
        return;
      }

      if (Array.isArray(instance?.events) && instance?.events.includes(configEv)) {
        this.socket.of(`/${instanceName}`).emit(event, message);

        if (logEnabled) {
          this.logger.log({ local: `${origin}.sendData-Websocket`, ...message });
        }
      }
    } catch (err) {
      if (logEnabled) {
        this.logger.log(err);
      }
    }
  }
}
